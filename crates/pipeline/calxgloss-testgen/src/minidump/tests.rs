//! The minidump lane's tests (P23.7, issue #401): a hand-assembled
//! dump parses to the picture it tells — threads, contexts, fault,
//! modules — and a fault landing exactly on a target export entry
//! folds into a filed case through the record-and-replay machinery.
//! Everything else — a near miss, a mismatched module identity, an
//! unmaterializable pointer, a truncated stack, a float argument — is
//! refused with its reason named, never silently dropped.
//!
//! The reader is tested only through the picture a dump tells: what
//! threads it carries, what contexts they hold, what fault it records,
//! what modules it names. Nothing pins the reader's internal shape.

use std::path::Path;

use calxgloss_testfixtures::minidump::{ContextBytes, MinidumpBuilder};
use calxgloss_testfixtures::{TARGET_FILE_NAME, fixture_target_path};
use calxgloss_types::{CaseOrigin, Export, TestCase, UnknownKind, UnknownOrigin};
use sha2::{Digest, Sha256};

use super::{Minidump, fold_minidumps};
use crate::generator::TestGenerator;
use crate::pe::PeImage;
use crate::record_replay::{RefusalReason, Replay, ReplayOutcome};

/// The faulting thread's id in every fixture dump here.
const THREAD: u32 = 4096;
/// Where the dump's module sits: deliberately not the PE's preferred
/// base, so the fold must translate, not assume.
const DUMP_BASE: u64 = 0x1000_0000;
/// Where the faulting thread's captured stack sits.
const STACK_BASE: u64 = 0x0012_3000;
/// Where a captured buffer sits, for pointer arguments.
const BUFFER: u64 = 0x2000_0000;
/// The exception code of an access violation.
const ACCESS_VIOLATION: u32 = 0xC000_0005;

/// The real fixture target, parsed — the identity the dumps must match.
fn target() -> PeImage {
    let path = fixture_target_path().expect("the fixture target is built");
    PeImage::parse(&path).expect("the fixture target parses")
}

/// The entry-point VA a listing would carry for one of the target's
/// exports: Kuna spells addresses at the preferred image base.
fn entry_point(pe: &PeImage, name: &str) -> Export {
    let rva = pe.export_rva_by_name(name).expect("the fixture exports it");
    Export {
        name: name.to_string(),
        address: pe.image_base() + u64::from(rva),
        signature: String::new(),
    }
}

/// A listing carrying one export under a hand-written signature.
fn listing(pe: &PeImage, name: &str, signature: &str) -> Vec<Export> {
    let mut export = entry_point(pe, name);
    export.signature = signature.to_string();
    vec![export]
}

/// The rva of one export's entry inside the target.
fn rva_of(pe: &PeImage, name: &str) -> u64 {
    u64::from(pe.export_rva_by_name(name).expect("the fixture exports it"))
}

/// A context entering one export with two register arguments.
fn context(rcx: u64, rdx: u64) -> ContextBytes {
    ContextBytes {
        rcx,
        rdx,
        rsp: STACK_BASE + 0x40,
        rbp: STACK_BASE + 0x40,
        ..Default::default()
    }
}

/// The same context caught at an entry point: rip sits on the entry.
fn context_at(rcx: u64, rdx: u64, entry_va: u64) -> ContextBytes {
    ContextBytes {
        rip: entry_va,
        ..context(rcx, rdx)
    }
}

/// A crash dump: the target module at `DUMP_BASE` under its full
/// loaded path, one faulting thread with its context and a captured
/// stack, and the exception naming the thread, the code, and the
/// fault address.
fn crash_dump(pe: &PeImage, fault: u64, ctx: &ContextBytes, stack: &[u8]) -> Vec<u8> {
    MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(THREAD, *ctx, STACK_BASE, stack.to_vec())
        .exception_with_context(THREAD, ACCESS_VIOLATION, fault, *ctx)
        .processor_architecture(9)
        .build()
}

/// Fold one dump through the lane against a temp-dir workspace.
async fn fold_dump(
    workspace: &Path,
    exports: &[Export],
    dump_bytes: &[u8],
    replay: &Replay<'_>,
) -> super::MinidumpFolded {
    let dump_path = workspace.join("crash.dmp");
    std::fs::write(&dump_path, dump_bytes).expect("dump written");
    let generator = TestGenerator::new(workspace);
    let dll = fixture_target_path().expect("the fixture target is built");
    let folded = fold_minidumps(
        &generator,
        TARGET_FILE_NAME,
        &dll,
        exports,
        &[&dump_path],
        replay,
    )
    .await
    .expect("the lane folds a well-formed dump");
    assert_eq!(folded.len(), 1, "one dump folds to one picture");
    folded.into_iter().next().expect("checked length")
}

/// A replay seam that observes every case and hands back a return.
fn observed(returned: serde_json::Value) -> impl Fn(&str, &TestCase) -> ReplayOutcome {
    move |_export, _case| ReplayOutcome::Observed {
        returned: returned.clone(),
        side_effects: Vec::new(),
        api_calls: Vec::new(),
    }
}

/// The digest the lane must stamp every record with.
fn expected_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sum = hasher.finalize();
    let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("sha256:{hex}")
}

// -------------------------------------------------------------------
// The reader: the picture a dump tells, and nothing else.
// -------------------------------------------------------------------

#[test]
fn a_dump_tells_its_threads_fault_and_module_picture() {
    let pe = target();
    let idle = ContextBytes {
        rip: 0x7FFE_1000,
        ..Default::default()
    };
    let entry_va = DUMP_BASE + rva_of(&pe, "fixture_init");
    let faulting = context_at(42, 7, entry_va);
    let bytes = MinidumpBuilder::new()
        .module("C:\\Windows\\ntdll.dll", 0x7FFE_0000, 0x1000, 0x1)
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(100, idle, 0x0011_0000, vec![0u8; 16])
        .thread(THREAD, faulting, STACK_BASE, vec![0xABu8; 32])
        .exception_with_context(THREAD, ACCESS_VIOLATION, entry_va, faulting)
        .memory(BUFFER, b"hello".to_vec())
        .processor_architecture(9)
        .build();

    let dump = Minidump::parse_bytes(&bytes).expect("a well-formed dump parses");
    assert_eq!(dump.processor_architecture, Some(9), "the dump says AMD64");

    // Two threads, and each one's context is its own.
    assert_eq!(dump.threads().len(), 2);
    let idle_thread = dump.thread(100).expect("the idle thread is there");
    let faulting_thread = dump.thread(THREAD).expect("the faulting thread is there");
    assert_eq!(idle_thread.context.map(|c| c.rip), Some(0x7FFE_1000));
    let ctx = faulting_thread
        .context
        .expect("the thread carries its context");
    assert_eq!(ctx.rcx, 42);
    assert_eq!(ctx.rdx, 7);
    assert_eq!(
        ctx.rip, entry_va,
        "the context caught the thread at the entry"
    );
    assert_eq!(faulting_thread.stack(), (STACK_BASE, &[0xABu8; 32][..]));

    // The fault: which thread, which code, which address.
    let exception = dump.exception().expect("the dump carries an exception");
    assert_eq!(exception.thread_id, THREAD);
    assert_eq!(exception.code, ACCESS_VIOLATION);
    assert_eq!(exception.fault_address, entry_va);
    assert_eq!(exception.context.expect("with its context").rip, entry_va);

    // The module picture: the dump names what was loaded, with the
    // identity stamps a crash reader compares.
    assert_eq!(dump.modules().len(), 2);
    let module = dump
        .module_at(entry_va)
        .expect("the fault lands in a module");
    assert!(module.name.ends_with("fixture_target.dll"));
    assert_eq!(module.base_of_image, DUMP_BASE);
    assert_eq!(module.size_of_image, pe.size_of_image());
    assert_eq!(module.time_date_stamp, pe.time_date_stamp());
    assert!(dump.module_at(0x7FFE_0100).is_some(), "ntdll is named too");

    // And the captured memory answers "what bytes at that address".
    assert_eq!(dump.memory_window(BUFFER), Some(&b"hello"[..]));
    assert_eq!(
        dump.memory_window(BUFFER).map(|w| w.len()),
        Some(5),
        "the window stops where the capture stops"
    );
    assert_eq!(
        dump.memory_window(0x3000_0000),
        None,
        "nothing was captured there"
    );
}

#[test]
fn files_that_are_not_minidumps_are_refused_by_name() {
    let error = format!(
        "{:#}",
        Minidump::parse_bytes(b"PDMP not a dump").expect_err("magic checked")
    );
    assert!(error.contains("not a minidump"), "{error}");

    let error = format!(
        "{:#}",
        Minidump::parse_bytes(b"\x7fELF\x02\x01\x01core").expect_err("an ELF core refused")
    );
    assert!(
        error.contains("ELF core") && error.contains("out of scope"),
        "{error}"
    );

    let error = format!(
        "{:#}",
        Minidump::parse_bytes(b"MDMP").expect_err("a truncated header refused")
    );
    assert!(error.contains("not a minidump"), "{error}");
}

// -------------------------------------------------------------------
// The claim gate: what the lane takes at face value, and what it
// leaves an unclaimed mapping candidate.
// -------------------------------------------------------------------

#[tokio::test]
async fn a_fault_exactly_on_an_export_entry_folds_into_a_filed_case() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let dump_bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_init"),
        &context(42, 7),
        &[],
    );
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );
    let seam = observed(serde_json::json!(49));
    let folded = fold_dump(
        workspace.path(),
        &exports,
        &dump_bytes,
        &Replay::Fake(&seam),
    )
    .await;

    assert_eq!(
        folded.digest,
        expected_digest(&dump_bytes),
        "the digest names the dump"
    );
    assert_eq!(folded.candidates_unclaimed, 0);
    assert_eq!(folded.report.events_seen, 1);
    assert_eq!(folded.report.cases_mined, 1);
    assert!(
        folded.report.refusals.is_empty(),
        "{:?}",
        folded.report.refusals
    );
    assert!(folded.unknown_records.is_empty());

    // The filed case names the dump digest, the thread, and the fault
    // address it was mined from.
    let generator = TestGenerator::new(workspace.path());
    let rows = generator
        .load_baseline(TARGET_FILE_NAME, "fixture_init")
        .expect("the case is filed");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].test_case.origin,
        CaseOrigin::MinedMinidump {
            dump_digest: folded.digest.clone(),
            thread_id: THREAD,
            fault_address: DUMP_BASE + rva_of(&pe, "fixture_init"),
        }
    );
    // The vector arrived as the convention left it: 42 and 7.
    assert_eq!(rows[0].actual_return, serde_json::json!(49));
}

#[tokio::test]
async fn a_fifth_argument_arrives_from_its_slot_above_the_shadow_space() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // A context caught at an entry has rsp pointing at the pushed
    // return address: return address, the caller's 32-byte shadow
    // space, and only then the fifth argument's slot. The shadow slots
    // are zeros and the fifth argument carries a value nothing else
    // could produce — a read eight bytes short would see the zeros.
    let mut stack = vec![0u8; 0x30];
    stack[0x28..0x30].copy_from_slice(&1_234_567_890u64.to_le_bytes());
    let ctx = ContextBytes {
        rcx: 1,
        rdx: 2,
        r8: 3,
        r9: 4,
        rsp: STACK_BASE,
        rip: DUMP_BASE + rva_of(&pe, "fixture_ordered"),
        ..Default::default()
    };
    let bytes = crash_dump(&pe, ctx.rip, &ctx, &stack);
    let exports = listing(
        &pe,
        "fixture_ordered",
        "int __stdcall fixture_ordered(int a, int b, int c, int d, int e)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert!(
        folded.report.refusals.is_empty(),
        "{:?}",
        folded.report.refusals
    );
    assert_eq!(folded.report.cases_mined, 1);

    // The filed case's fifth parameter was fed from the slot at
    // rsp + 0x28: the stack named it, and it reached the replay.
    let generator = TestGenerator::new(workspace.path());
    let rows = generator
        .load_baseline(TARGET_FILE_NAME, "fixture_ordered")
        .expect("the case is filed");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].test_case.inputs.get("e"),
        Some(&serde_json::json!(1_234_567_890)),
        "the fifth argument arrived whole from above the shadow space"
    );
}

#[tokio::test]
async fn a_twin_dump_dedups_into_the_filed_case_exactly_as_the_ingest_does() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let dump_bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_init"),
        &context(42, 7),
        &[],
    );
    let first = workspace.path().join("first.dmp");
    let second = workspace.path().join("second.dmp");
    std::fs::write(&first, &dump_bytes).expect("dump written");
    std::fs::write(&second, &dump_bytes).expect("dump written");
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );
    let seam = observed(serde_json::json!(49));
    let generator = TestGenerator::new(workspace.path());
    let dll = fixture_target_path().expect("the fixture target is built");
    let folded = fold_minidumps(
        &generator,
        TARGET_FILE_NAME,
        &dll,
        &exports,
        &[&first, &second],
        &Replay::Fake(&seam),
    )
    .await
    .expect("the lane folds both dumps");

    assert_eq!(folded.len(), 2, "each dump answers with its own report");
    assert_eq!(folded[0].report.cases_mined, 1);
    assert_eq!(
        folded[1].report.cases_mined, 0,
        "a twin files no second case"
    );
    assert_eq!(
        folded[1].report.cases_deduplicated, 1,
        "the twin dedups into the row the first dump filed"
    );
    let rows = generator
        .load_baseline(TARGET_FILE_NAME, "fixture_init")
        .expect("the suite is filed");
    assert_eq!(rows.len(), 1, "the filed suite keeps one row for the twins");
}

#[tokio::test]
async fn a_near_miss_fault_and_a_fault_outside_the_module_claim_nothing() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );

    // A fault one instruction past the entry: the dump proves a call
    // happened somewhere, not which export received it.
    let near = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_init") + 4,
        &context(42, 7),
        &[],
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &near, &Replay::Fake(&seam)).await;
    assert_eq!(folded.candidates_unclaimed, 1);
    assert_eq!(folded.report.events_seen, 0, "nothing entered the log");
    assert_eq!(folded.report.cases_mined, 0);
    let reason = folded.candidate_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains("not exactly on a target export entry"),
        "{reason}"
    );

    // A fault outside the matched module's mapped range claims nothing
    // either — the count is stated, never folded silently.
    let elsewhere = crash_dump(
        &pe,
        DUMP_BASE + u64::from(pe.size_of_image()) + 0x1000,
        &context(1, 2),
        &[],
    );
    let folded = fold_dump(workspace.path(), &exports, &elsewhere, &Replay::Fake(&seam)).await;
    assert_eq!(folded.candidates_unclaimed, 1);
    let reason = folded.candidate_reason.as_deref().unwrap_or_default();
    assert!(reason.contains("outside the matched module"), "{reason}");

    // Nothing was replayed anywhere, so no suite was filed.
    assert!(!workspace.path().join("re/baseline").exists());
}

#[tokio::test]
async fn a_mismatched_module_identity_claims_nothing() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // The same file name with a different mapped size: a different
    // build of the DLL, not the one on disk.
    let bytes = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            0x1234,
            pe.time_date_stamp(),
        )
        .thread(THREAD, context(1, 2), STACK_BASE, vec![])
        .exception_with_context(
            THREAD,
            ACCESS_VIOLATION,
            DUMP_BASE + rva_of(&pe, "fixture_init"),
            context(1, 2),
        )
        .processor_architecture(9)
        .build();
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;
    assert_eq!(folded.candidates_unclaimed, 1);
    let reason = folded.candidate_reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains(&format!(
            "no module matching the target `{TARGET_FILE_NAME}`"
        )),
        "{reason}"
    );
    assert_eq!(folded.report.cases_mined, 0);
}

// -------------------------------------------------------------------
// Vectors the dump cannot express in the replay vocabulary: refused,
// with the reason named on the record.
// -------------------------------------------------------------------

#[tokio::test]
async fn a_pointer_with_no_captured_target_is_refused_by_name() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // rcx names an address the dump never captured: nothing to
    // materialize at replay.
    let bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_describe"),
        &context(0xDEAD_0000, 0),
        &[],
    );
    let exports = listing(
        &pe,
        "fixture_describe",
        "int __stdcall fixture_describe(char *buffer)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert_eq!(folded.report.events_seen, 1);
    assert_eq!(folded.report.cases_mined, 0);
    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::UnmaterializablePointer
    );
    assert_eq!(folded.report.refusals[0].sequence, Some(u64::from(THREAD)));
    assert_eq!(folded.unknown_records.len(), 1);
    assert_eq!(folded.unknown_records[0].kind, UnknownKind::CaptureRefused);
    assert!(
        folded.unknown_records[0]
            .question
            .contains("unmaterializable-pointer"),
        "{}",
        folded.unknown_records[0].question
    );
    assert!(
        folded.unknown_records[0]
            .question
            .contains(&expected_digest(&bytes)),
        "the record names the dump it came from"
    );
}

#[tokio::test]
async fn a_pointer_window_over_the_capture_bound_refuses_as_truncated() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // The dump holds 70 KiB at the target address: a dump can never
    // prove a buffer whole over the 64 KiB capture bound, so the
    // reconstruction stamps the truncation and the fold refuses.
    let bytes = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(THREAD, context(BUFFER, 0), STACK_BASE, vec![])
        .exception_with_context(
            THREAD,
            ACCESS_VIOLATION,
            DUMP_BASE + rva_of(&pe, "fixture_describe"),
            context(BUFFER, 0),
        )
        .memory(BUFFER, vec![0x5Au8; 70 * 1024])
        .processor_architecture(9)
        .build();
    let exports = listing(
        &pe,
        "fixture_describe",
        "int __stdcall fixture_describe(char *buffer)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::TruncatedCapture
    );
    assert!(
        folded.report.summary().contains("1 truncation stated"),
        "{}",
        folded.report.summary()
    );
}

#[tokio::test]
async fn a_stack_cut_off_before_its_argument_slots_is_refused_by_name() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // Five parameters: the fifth arrives in a stack slot above the
    // shadow space. The dump's stack capture stops short of it.
    let bytes = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(
            THREAD,
            ContextBytes {
                rcx: 1,
                rdx: 2,
                r8: 3,
                r9: 4,
                rsp: STACK_BASE + 0x10,
                ..Default::default()
            },
            STACK_BASE,
            vec![0u8; 0x28],
        )
        .exception_with_context(
            THREAD,
            ACCESS_VIOLATION,
            DUMP_BASE + rva_of(&pe, "fixture_ordered"),
            ContextBytes {
                rcx: 1,
                rdx: 2,
                r8: 3,
                r9: 4,
                rsp: STACK_BASE + 0x10,
                ..Default::default()
            },
        )
        .processor_architecture(9)
        .build();
    let exports = listing(
        &pe,
        "fixture_ordered",
        "int __stdcall fixture_ordered(int a, int b, int c, int d, int e)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::TruncatedCapture
    );
    assert_eq!(folded.report.refusals[0].sequence, Some(u64::from(THREAD)));
    assert!(
        folded.report.summary().contains("1 truncation stated"),
        "{}",
        folded.report.summary()
    );
    assert_eq!(folded.unknown_records.len(), 1);
    assert!(
        folded.unknown_records[0]
            .question
            .contains("stopped before its argument slots"),
        "{}",
        folded.unknown_records[0].question
    );
}

#[tokio::test]
async fn a_float_argument_is_refused_by_name() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    // A double arrives in the first argument register: the capture
    // vocabulary and the scalar replay carry no float, so the lane
    // says so with the f64 tag rather than re-encoding the value.
    let bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_tick"),
        &context(0x4000_0000_0000_0000, 0),
        &[],
    );
    let exports = listing(
        &pe,
        "fixture_tick",
        "int __stdcall fixture_tick(double ratio)",
    );
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::FloatArgument
    );
    assert!(
        folded.unknown_records[0]
            .question
            .contains("float-argument"),
        "{}",
        folded.unknown_records[0].question
    );
}

#[tokio::test]
async fn a_vector_with_no_parseable_signature_is_refused_by_name() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_status"),
        &context(9, 0),
        &[],
    );
    // The listing carries this export with a prototype that never
    // arrived whole: no vector can be named against it, and the fold
    // says so by name rather than guessing a shape.
    let exports = listing(&pe, "fixture_status", "int __stdcall fixture_status(int");
    let seam = observed(serde_json::json!(0));
    let folded = fold_dump(workspace.path(), &exports, &bytes, &Replay::Fake(&seam)).await;

    assert_eq!(folded.report.refusals.len(), 1);
    assert_eq!(
        folded.report.refusals[0].reason,
        RefusalReason::NoParseableSignature
    );
    assert_eq!(folded.report.cases_mined, 0);
}

// -------------------------------------------------------------------
// A replay that faults names the crash reproduction, origin-bound to
// the dump and the thread.
// -------------------------------------------------------------------

#[tokio::test]
async fn a_replay_that_faults_files_a_crash_reproduction_naming_the_dump_and_thread() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let dump_bytes = crash_dump(
        &pe,
        DUMP_BASE + rva_of(&pe, "fixture_init"),
        &context(42, 7),
        &[],
    );
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );
    let seam = |_export: &str, _case: &TestCase| ReplayOutcome::Faulted {
        detail: "read access violation at address 0x0".to_string(),
    };
    let folded = fold_dump(
        workspace.path(),
        &exports,
        &dump_bytes,
        &Replay::Fake(&seam),
    )
    .await;

    assert_eq!(
        folded.report.cases_mined, 0,
        "a fault is not an observation"
    );
    assert_eq!(folded.unknown_records.len(), 1);
    let record = &folded.unknown_records[0];
    assert_eq!(record.kind, UnknownKind::CrashReproduction);
    assert_eq!(
        record.origin,
        UnknownOrigin::Capture {
            capture_id: expected_digest(&dump_bytes),
            event_sequence: Some(u64::from(THREAD)),
        },
        "the record traces back to the dump and the faulting thread"
    );
    assert!(
        record.question.contains("fixture_init"),
        "{}",
        record.question
    );
    assert!(
        record.question.contains(&expected_digest(&dump_bytes)),
        "{}",
        record.question
    );
}

// -------------------------------------------------------------------
// Files that are not dumps, and dumps that are not AMD64: the lane
// refuses by name.
// -------------------------------------------------------------------

#[tokio::test]
async fn a_core_file_and_a_foreign_architecture_are_refused_by_name() {
    let pe = target();
    let workspace = tempfile::tempdir().expect("temp dir");
    let exports = listing(
        &pe,
        "fixture_init",
        "int __stdcall fixture_init(int a, int b)",
    );
    let generator = TestGenerator::new(workspace.path());
    let dll = fixture_target_path().expect("the fixture target is built");
    let seam = observed(serde_json::json!(0));

    std::fs::write(
        workspace.path().join("app-core"),
        b"\x7fELF\x02\x01\x01core",
    )
    .expect("core written");
    let error = format!(
        "{:#}",
        fold_minidumps(
            &generator,
            TARGET_FILE_NAME,
            &dll,
            &exports,
            &[&workspace.path().join("app-core")],
            &Replay::Fake(&seam),
        )
        .await
        .expect_err("an ELF core is out of scope, and the file is named")
    );
    assert!(error.contains("app-core"), "{error}");
    assert!(
        error.contains("ELF core") && error.contains("out of scope"),
        "{error}"
    );

    // An x86 dump: the lane mines AMD64 vectors and says so.
    let bytes = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            DUMP_BASE,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .processor_architecture(0)
        .build();
    std::fs::write(workspace.path().join("x86.dmp"), &bytes).expect("dump written");
    let error = format!(
        "{:#}",
        fold_minidumps(
            &generator,
            TARGET_FILE_NAME,
            &dll,
            &exports,
            &[&workspace.path().join("x86.dmp")],
            &Replay::Fake(&seam),
        )
        .await
        .expect_err("a foreign architecture is refused by name")
    );
    assert!(error.contains("AMD64"), "{error}");
}
