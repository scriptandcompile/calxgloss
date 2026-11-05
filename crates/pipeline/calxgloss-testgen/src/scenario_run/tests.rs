//! Pins for the scenario-run capture seam (P24.3, issue #404).
//!
//! The filesystem classification pins run on the host alone: they weigh
//! content, never existence. The full-run pins need Wine and the fixture
//! console EXE, so they stand ignored like the baseline Wine pins; the
//! missing-Wine pin is never gated — failing by name is what makes an
//! absent toolchain a stated failure, never a hang.

use std::collections::BTreeMap;
use std::path::Path;

use calxgloss_types::{
    ExitDisposition, FileChange, NormalizationRules, ScenarioContract, ScriptedInput,
    ScriptedInteraction,
};

use super::capture_scenario;
use super::files::{classify_paths, content_identity, snapshot_paths};
use crate::wine::WineRunner;

fn contract(name: &str) -> ScenarioContract {
    ScenarioContract {
        name: name.to_string(),
        working_dir: ".".to_string(),
        env: BTreeMap::new(),
        argv: Vec::new(),
        interactions: Vec::new(),
        cols: 80,
        rows: 24,
        observation_paths: Vec::new(),
        idle_timeout_ms: 5_000,
        max_run_ms: 15_000,
        finalization_grace_ms: 1_000,
        max_output_bytes: 64 * 1024,
        normalization: NormalizationRules {
            version: "1".to_string(),
            literal_replacements: Vec::new(),
            port_patterns: Vec::new(),
        },
    }
}

// ============================================================
// Filesystem classification: content identity, four change classes
// ============================================================

fn write_file(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).expect("the fixture file should be writable");
}

#[test]
fn a_created_path_carries_its_after_side_size_digest_and_blocks() {
    let dir = tempfile::tempdir().expect("a run dir");
    let declared = ["out.dat".to_string()];

    let before = snapshot_paths(dir.path(), &declared);
    write_file(dir.path(), "out.dat", b"12345");
    let after = snapshot_paths(dir.path(), &declared);

    let entries = classify_paths(&declared, &before, &after);
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.path, "out.dat");
    assert_eq!(entry.change, FileChange::Created);
    assert_eq!(entry.size_bytes, Some(5), "the after side's size");
    assert_eq!(
        entry.sha256.as_deref(),
        Some(sha256_hex(b"12345").as_str()),
        "the after side's whole-file digest"
    );
    assert_eq!(entry.block_hashes.len(), 1, "5 bytes are one 4 KiB block");
    assert_eq!(entry.block_hashes[0], sha256_hex(b"12345"));
}

#[test]
fn a_deleted_path_carries_its_before_side_identity() {
    let dir = tempfile::tempdir().expect("a run dir");
    let declared = ["gone.dat".to_string()];

    write_file(dir.path(), "gone.dat", b"old-bytes");
    let before = snapshot_paths(dir.path(), &declared);
    std::fs::remove_file(dir.path().join("gone.dat")).expect("the file should be removable");
    let after = snapshot_paths(dir.path(), &declared);

    let entries = classify_paths(&declared, &before, &after);
    let entry = &entries[0];
    assert_eq!(entry.change, FileChange::Deleted);
    assert_eq!(
        entry.sha256.as_deref(),
        Some(sha256_hex(b"old-bytes").as_str()),
        "the deleted entry names the before side's digest — the after side is gone"
    );
    assert_eq!(entry.size_bytes, Some(9), "the before side's size");
    assert_eq!(entry.block_hashes.len(), 1);
}

#[test]
fn a_modified_path_shows_which_blocks_moved() {
    let dir = tempfile::tempdir().expect("a run dir");
    let declared = ["mix.dat".to_string()];
    let head = vec![b'A'; 4096];
    let tail = b"first-tail";

    let mut original = head.clone();
    original.extend_from_slice(tail);
    write_file(dir.path(), "mix.dat", &original);
    let before = snapshot_paths(dir.path(), &declared);

    let mut rewritten = head.clone();
    rewritten.extend_from_slice(b"second-tail");
    write_file(dir.path(), "mix.dat", &rewritten);
    let after = snapshot_paths(dir.path(), &declared);

    let entries = classify_paths(&declared, &before, &after);
    let entry = &entries[0];
    assert_eq!(entry.change, FileChange::Modified);
    let before_blocks = &content_identity(&dir.path().join("mix.dat"))
        .expect("the rewritten file reads")
        .block_hashes;
    assert_eq!(
        entry.block_hashes, *before_blocks,
        "the modified entry names the after side's blocks"
    );
    assert_eq!(
        before_blocks[0],
        sha256_hex(&head),
        "the untouched 4 KiB block keeps its digest — the block digests show \
         exactly which block moved"
    );
    assert_eq!(
        before_blocks.len(),
        2,
        "4096 + 11 bytes stand as two blocks"
    );
    assert_ne!(before_blocks[1], sha256_hex(tail), "the second block moved");
}

#[test]
fn a_file_is_compared_by_content_not_by_being_written_again() {
    // The standing honesty rule: files are compared by content, not
    // existence. A run that writes the same bytes back is *unchanged*,
    // not modified.
    let dir = tempfile::tempdir().expect("a run dir");
    let declared = ["same.dat".to_string()];

    write_file(dir.path(), "same.dat", b"steady");
    let before = snapshot_paths(dir.path(), &declared);
    write_file(dir.path(), "same.dat", b"steady");
    let after = snapshot_paths(dir.path(), &declared);

    let entries = classify_paths(&declared, &before, &after);
    assert_eq!(
        entries[0].change,
        FileChange::Unchanged,
        "identical content across the run reads unchanged, however often it was written"
    );
    assert_eq!(
        entries[0].sha256.as_deref(),
        Some(sha256_hex(b"steady").as_str())
    );
}

#[test]
fn a_path_that_stands_on_neither_side_states_its_emptiness() {
    // A declared path the never touched is still one honest entry: the
    // unchanged class with no side to name — never an implied content.
    let dir = tempfile::tempdir().expect("a run dir");
    let declared = ["never.dat".to_string()];

    let before = snapshot_paths(dir.path(), &declared);
    let after = snapshot_paths(dir.path(), &declared);
    let entries = classify_paths(&declared, &before, &after);
    assert_eq!(entries[0].change, FileChange::Unchanged);
    assert_eq!(entries[0].size_bytes, None, "no side, no size");
    assert_eq!(entries[0].sha256, None, "no side, no digest");
    assert!(entries[0].block_hashes.is_empty(), "no side, no blocks");
}

#[test]
fn block_digests_cover_the_exact_4kib_window_boundaries() {
    // 4096 bytes stand as exactly one block; 4097 as two, the second
    // being the one-byte remainder's digest.
    let dir = tempfile::tempdir().expect("a run dir");
    write_file(dir.path(), "edge.bin", &vec![b'x'; 4097]);
    let identity = content_identity(&dir.path().join("edge.bin")).expect("the file reads");
    assert_eq!(identity.size_bytes, 4097);
    assert_eq!(identity.block_hashes.len(), 2);
    assert_eq!(identity.block_hashes[0], sha256_hex(&vec![b'x'; 4096]));
    assert_eq!(identity.block_hashes[1], sha256_hex(b"x"));
    assert_eq!(identity.sha256, sha256_hex(&vec![b'x'; 4097]));
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ============================================================
// Output cap: stored bytes are what the cap weighs
// ============================================================

#[test]
fn the_cap_never_stores_more_than_it_holds_across_a_char_boundary() {
    // The honesty accounting: the cap weighs the stored, lossy-rendered
    // bytes — not the raw read — so a boundary cut mid-codepoint can
    // never inflate the record past the cap (a raw-byte cut would have
    // stored a replacement char and overflowed the cap by a byte).
    let mut recording = super::Recording::new(3);
    recording.record(b"ab\xc3\xa9"); // 'é' in UTF-8: 4 raw bytes, 4 rendered bytes
    let observation = recording.into_observation();
    let stored: usize = observation.chunks.iter().map(String::len).sum();
    assert_eq!(observation.chunks, vec!["ab".to_string()]);
    assert!(
        stored <= 3,
        "the record never claims more than it holds: {stored} stored"
    );
    assert!(
        observation.output_capped,
        "the crossing chunk marks the truncation"
    );
    assert_eq!(
        observation.cap_bytes,
        Some(3),
        "a capped capture names its cap in the record"
    );
}

#[test]
fn an_uncapped_recording_states_no_cap_at_all() {
    let mut recording = super::Recording::new(64);
    recording.record(b"hello");
    let observation = recording.into_observation();
    assert!(!observation.output_capped);
    assert_eq!(
        observation.cap_bytes, None,
        "an uncapped record says nothing about caps"
    );
}

// ============================================================
// Missing Wine: ungated, named, never a hang
// ============================================================

#[test]
fn a_missing_wine_fails_the_capture_by_name_before_anything_runs() {
    // The standing preflight line governs: a capture without Wine fails
    // naming the Wine it looked for, before a run dir is touched and
    // before any process exists to hang.
    let dirs = tempfile::tempdir().expect("a workspace dir");
    let program = dirs.path().join("no-such.exe");
    write_file(dirs.path(), "no-such.exe", b"not even a PE");
    let wine = WineRunner::new(dirs.path()).with_wine_bin("calxgloss-no-such-wine");

    let err = capture_scenario(
        &program,
        &dirs.path().join("run"),
        &contract("boot"),
        &wine,
        1,
    )
    .expect_err("a missing Wine must fail the capture");
    let message = err.to_string();
    assert!(
        message.contains("calxgloss-no-such-wine"),
        "the failure names the Wine it looked for: {message}"
    );
    assert!(
        message.contains("CALXGLOSS_WINE"),
        "the failure carries the standing preflight guidance: {message}"
    );
}

// ============================================================
// Full runs against the fixture console EXE (Wine-gated)
// ============================================================

fn fixture_exe_path() -> std::path::PathBuf {
    calxgloss_testfixtures::console_target_path()
        .expect("the build script should have compiled the fixture console exe")
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_clean_fixture_run_captures_exit_output_files_acks_and_pairing() {
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");
    write_file(&run_dir, "old.dat", b"old-bytes");

    let mut c = contract("boot-and-exit");
    // The idle window must outlast Wine's own boot: the window closes a
    // silent *run*, and a run spent starting is not yet idle-silent.
    c.idle_timeout_ms = 15_000;
    c.max_run_ms = 30_000;
    c.interactions = vec![
        input_at(1_000, "echo hello-scene"),
        input_at(1_500, "write new.dat new-content"),
        input_at(2_000, "delete old.dat"),
        input_at(2_500, "exit 7"),
    ];
    c.observation_paths = vec!["new.dat".to_string(), "old.dat".to_string()];

    let wine = WineRunner::new(stage.path());
    let capture =
        capture_scenario(&program, &run_dir, &c, &wine, 42).expect("the fixture runs under Wine");

    assert_eq!(capture.scenario, "boot-and-exit");
    assert_eq!(
        capture.filed_at, 42,
        "the filing clock rides in from the caller"
    );

    let exit = capture.exit.expect("the exit block stands");
    assert_eq!(
        exit.disposition,
        ExitDisposition::Exited,
        "the run ended on its own"
    );
    assert_eq!(exit.exit_code, Some(7), "the fixture's declared code lands");

    let terminal = capture.terminal.expect("the terminal block stands");
    let joined = terminal.chunks.join("");
    assert!(
        joined.contains("hello-scene"),
        "the fixture echoed the scripted input back: {joined}"
    );
    assert!(!terminal.output_capped, "a small run never reports the cap");

    let fs = capture.filesystem.expect("the filesystem block stands");
    assert_eq!(fs.entries.len(), 2);
    let created = fs
        .entries
        .iter()
        .find(|e| e.path == "new.dat")
        .expect("the declared path reads");
    assert_eq!(created.change, FileChange::Created);
    assert_eq!(
        created.size_bytes,
        Some(12),
        "'new-content' plus the fixture's line terminator"
    );
    let deleted = fs
        .entries
        .iter()
        .find(|e| e.path == "old.dat")
        .expect("the declared path reads");
    assert_eq!(deleted.change, FileChange::Deleted);
    assert_eq!(
        deleted.sha256.as_deref(),
        Some(sha256_hex(b"old-bytes").as_str()),
        "the deleted path names its before-side content"
    );

    let interaction = capture.interaction.expect("the interaction block stands");
    assert_eq!(
        interaction.acknowledged_at_ms,
        vec![1_000, 1_500, 2_000, 2_500],
        "every interaction delivered while the run stood is acknowledged at its offset"
    );

    let pairing = capture.pairing.expect("the pairing stamps stand");
    let program_bytes = std::fs::read(&program).expect("the staged program reads");
    assert_eq!(
        pairing.program_sha256,
        sha256_hex(&program_bytes),
        "the capture stamps the sha256 of the very bytes it ran"
    );
    assert!(
        pairing.wine_version.contains("wine"),
        "the pairing names the Wine that ran it: {}",
        pairing.wine_version
    );

    let process = capture.process.expect("the process block stands");
    assert_eq!(process.samples.len(), 1, "one honest launch sample");
    assert!(!process.samples[0].name.is_empty());
    assert!(process.samples[0].pid > 0);
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_silent_run_is_closed_by_the_idle_window() {
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");

    let mut c = contract("idle");
    c.idle_timeout_ms = 400;
    c.max_run_ms = 30_000;

    let wine = WineRunner::new(stage.path());
    let started = std::time::Instant::now();
    let capture =
        capture_scenario(&program, &run_dir, &c, &wine, 1).expect("the idle close still files");
    let exit = capture.exit.as_ref().expect("the exit block stands");
    assert_eq!(
        exit.disposition,
        ExitDisposition::IdleTimeout,
        "the silent run ends by the idle window's name"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "the idle window acted, it did not wait out the max run"
    );
    assert_eq!(exit.exit_code, None, "a closed run carries no exit code");
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn oversized_output_caps_with_its_explicit_truncation_mark() {
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");

    let long_reply = format!("echo {}", "L".repeat(2_000));
    let mut c = contract("capped");
    c.max_output_bytes = 64;
    c.interactions = vec![input_at(1_000, &long_reply), input_at(1_500, "exit 0")];

    let wine = WineRunner::new(stage.path());
    let capture = capture_scenario(&program, &run_dir, &c, &wine, 1)
        .expect("a capped run still files its capture");
    let terminal = capture.terminal.expect("the terminal block stands");
    assert!(
        terminal.output_capped,
        "the run produced more than the cap, and the capture says so"
    );
    let recorded: usize = terminal.chunks.iter().map(|c| c.len()).sum();
    assert!(
        recorded <= 64,
        "the capture never claims more than the cap: {recorded} bytes stored"
    );
    assert_eq!(
        terminal.cap_bytes,
        Some(64),
        "the capped record names its cap in the document, not just on the print"
    );
    assert!(
        capture.exit.is_some(),
        "the capped run still names how it ended"
    );
}

fn input_at(at_ms: u64, text: &str) -> ScriptedInteraction {
    ScriptedInteraction {
        at_ms,
        kind: calxgloss_types::InteractionKind::Input {
            text: ScriptedInput::Text(text.to_string()),
        },
    }
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_byte_count_placeholder_input_is_never_delivered_nor_acknowledged() {
    // Secrets wait for the credential slices: the placeholder is stored,
    // never typed, and the capture never acknowledges it.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");

    let mut c = contract("secret-wait");
    c.interactions = vec![
        ScriptedInteraction {
            at_ms: 1_000,
            kind: calxgloss_types::InteractionKind::Input {
                text: ScriptedInput::ByteCount { bytes: 6 },
            },
        },
        input_at(1_500, "exit 0"),
    ];
    c.max_run_ms = 20_000;

    let wine = WineRunner::new(stage.path());
    let capture = capture_scenario(&program, &run_dir, &c, &wine, 1)
        .expect("the run files with the placeholder undelivered");
    let interaction = capture.interaction.expect("the interaction block stands");
    assert_eq!(
        interaction.acknowledged_at_ms,
        vec![1_500],
        "the placeholder is never delivered, so it is never acknowledged"
    );
    let joined = capture
        .terminal
        .expect("the terminal block")
        .chunks
        .join("");
    assert!(
        !joined.contains("secret"),
        "the placeholder's bytes never leak into the capture: {joined}"
    );
}
