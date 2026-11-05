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
    ExitDisposition, FileChange, FinalizationOutcome, NormalizationRules, ScenarioContract,
    ScenarioSignal, ScriptedInput, ScriptedInteraction, TerminalGeometry,
};

use super::TypedSecret;
use super::capture_scenario;
use super::capture_scenario_with_secrets;
use super::files::{classify_paths, content_identity, snapshot_paths};
use super::finalize_closed_run;
use crate::wine::WineRunner;
use crate::wine::owned::{OwnedProcess, OwnershipToken, Stopped};

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
    assert_eq!(
        exit.finalization, None,
        "a run that ended on its own was never finalized — the field reads unassessed"
    );

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
    // This pin shares the user's Wine prefix with the other run pins,
    // which cargo may run in parallel; a parallel pin's guest carries the
    // same prefix stamp and can appear in this run's samples. What must
    // hold under any contamination: samples are present, honest, and the
    // launch sample names the program the contract launched.
    assert!(
        !process.samples.is_empty(),
        "the run files its process samples"
    );
    assert!(
        process
            .samples
            .iter()
            .all(|sample| sample.pid > 0 && !sample.name.is_empty()),
        "every process sample names a live pid: {:?}",
        process.samples
    );
    assert!(
        process.samples[0].name == "fixture_console.exe",
        "the launch sample names the launched program: {:?}",
        process.samples[0]
    );
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
    assert_eq!(
        exit.finalization,
        Some(FinalizationOutcome::Signaled),
        "the idle close files how finalization reached the owned process"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "the idle window acted, it did not wait out the max run"
    );
    assert_eq!(exit.exit_code, None, "a closed run carries no exit code");
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_chatty_run_is_closed_by_the_max_run_window() {
    // The other named window: a run that keeps talking never goes idle,
    // so only the max-run duration may end it — and it ends *by that
    // name*, at the window, not at a stall.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");

    let mut c = contract("chatterbox");
    c.idle_timeout_ms = 2_000;
    c.max_run_ms = 5_000;
    // Each echo lands inside the idle window and restarts the silence
    // clock; the run never goes idle, so the max-run window owns its end.
    c.interactions = (0..4)
        .map(|i| input_at(500 + i * 1_000, &format!("echo tick-{i}")))
        .collect();

    let wine = WineRunner::new(stage.path());
    let started = std::time::Instant::now();
    let capture =
        capture_scenario(&program, &run_dir, &c, &wine, 1).expect("the max-run close still files");
    let exit = capture.exit.as_ref().expect("the exit block stands");
    assert_eq!(
        exit.disposition,
        ExitDisposition::Timeout,
        "the chatty run ends by the max-run window's name, never idle: {:?}",
        exit.disposition
    );
    assert_eq!(
        exit.finalization,
        Some(FinalizationOutcome::Signaled),
        "the closed run records that finalization reached exactly the owned process"
    );
    assert_eq!(exit.exit_code, None, "a closed run carries no exit code");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(c.max_run_ms),
        "the run lived to its window: {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(c.max_run_ms + 4_000),
        "the window acted at its close, grace and drain included: {:?}",
        started.elapsed()
    );
    let joined = capture
        .terminal
        .expect("the terminal block stands")
        .chunks
        .join("");
    assert!(
        joined.contains("tick-3"),
        "the run was still answering echoes when the window closed: {joined}"
    );
}

/// Stand up a private, fully set-up Wine prefix under `stage` and hand back
/// a runner pointed at it. The prefix is initialized through a bare
/// `wine cmd.exe /c exit` — the silent route every Wine-lane path takes
/// (see the module doc rule in `wine.rs`: never `wineboot -u` a fresh
/// prefix; that is the route that pops the GUI setup dialog). The pin's
/// own guest processes all carry this prefix's stamp in their inherited
/// environment, and the sampler scopes samples by that stamp — so the
/// process-sample assertions below stay exact no matter what the
/// shared-prefix pins are running in parallel.
fn warm_private_prefix(stage: &Path) -> WineRunner {
    let prefix = stage.join("wine-prefix");
    std::fs::create_dir_all(&prefix).expect("the private prefix dir stands");
    let status = std::process::Command::new("wine")
        .args(["cmd.exe", "/c", "exit"])
        .env("WINEPREFIX", &prefix)
        .env("WINEDEBUG", "-all")
        // Keep the Mono/Gecko installer components out of first-run setup
        // — the headless belt from the wine.rs module doc.
        .env("WINEDLLOVERRIDES", "mscoree,mshtml=")
        .status()
        .expect("the prefix initializer runs");
    assert!(status.success(), "the private prefix set up clean");
    WineRunner::new(stage).with_prefix(prefix)
}

/// Read the text out of recorded terminal chunks. A run that spawns a
/// child attaches another console client, and conhost then hides and
/// shows the cursor around its writes and redraws the line — the capture
/// keeps those bytes verbatim, as it must; the pin reads the visible
/// text by dropping each escape sequence (ESC `[` + parameter bytes up
/// to the final `@`..`~` byte).
fn visible_text(chunks: &[String]) -> String {
    let raw = chunks.join("");
    let mut text = String::new();
    let mut rest = raw.as_str();
    while let Some(at) = rest.find("\u{1b}[") {
        text.push_str(&rest[..at]);
        let params = &rest[at + 2..];
        match params.find(|c: char| ('@'..'~').contains(&c)) {
            Some(end) => rest = &params[end + 1..],
            None => rest = "",
        }
    }
    text.push_str(rest);
    text
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_run_that_spawns_a_child_records_the_child_in_its_process_samples() {
    // The process dimension earns its keep here: a program that spawns
    // children must show them in the record, not hide them. The fixture's
    // `spawn` verb launches a Wine guest child that stays alive well past
    // the run's own close, and the sampled rows must name it.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");
    let wine = warm_private_prefix(stage.path());

    let mut c = contract("spawner");
    c.idle_timeout_ms = 5_000;
    c.max_run_ms = 30_000;
    // A guest cmd.exe child, alive ~15s: the run closes on its idle
    // window long before the child does, so the sampling window always
    // sees it standing. (Wine has no sleep.exe; ping to loopback paces
    // one packet per second, so the child is slow-alive for a known
    // span — an unroutable target fails every send instantly and dies
    // before the next sweep.)
    c.interactions = vec![input_at(
        1_500,
        "spawn cmd.exe /c ping -n 15 127.0.0.1 >nul",
    )];

    let capture = capture_scenario(&program, &run_dir, &c, &wine, 1).expect("the spawn run files");
    let text = visible_text(&capture.terminal.expect("the terminal block stands").chunks);
    assert!(
        text.contains("spawned"),
        "the fixture acknowledged the child launch: {text}"
    );

    let process = capture.process.expect("the process block stands");
    assert!(
        process
            .samples
            .iter()
            .any(|sample| sample.name == "cmd.exe"),
        "the spawned guest child is among the run's process samples: {:?}",
        process.samples
    );
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_child_free_run_records_its_own_image_and_names_no_child() {
    // Honest emptiness: a run that spawns nothing still records the guest
    // process it actually ran — the observation is real, not a declared
    // placeholder — and it names no children it never had.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");
    let wine = warm_private_prefix(stage.path());

    let mut c = contract("child-free");
    c.idle_timeout_ms = 8_000;
    c.max_run_ms = 30_000;
    c.interactions = vec![input_at(1_500, "exit 3")];

    let capture = capture_scenario(&program, &run_dir, &c, &wine, 1).expect("the clean run files");
    assert_eq!(
        capture
            .exit
            .as_ref()
            .expect("the exit block stands")
            .exit_code,
        Some(3),
        "the fixture exited on cue"
    );

    let process = capture.process.expect("the process block stands");
    let launch = &process.samples[0];
    assert!(
        process
            .samples
            .iter()
            .any(|sample| sample.pid != launch.pid && sample.name == "fixture_console.exe"),
        "the run's own guest process is observed, not just declared: {:?}",
        process.samples
    );
    assert!(
        process
            .samples
            .iter()
            .all(|sample| sample.name != "cmd.exe" && sample.name != "ping"),
        "a child-free run names no children: {:?}",
        process.samples
    );
}

/// A stranger-PID close, run against a real live process the token no
/// longer answers to: the hard rule is proven end through the run lane's
/// own finalization step, and the record the step files names the
/// refusal by name. No Wine involved — the stranger needs only a live
/// pid and a stamp no live process can answer to.
#[cfg(target_os = "linux")]
#[test]
fn a_stranger_holding_the_pid_is_never_signaled_and_the_record_names_the_refusal() {
    let stranger = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("a stranger should spawn");
    // A forged launch stamp of 0 ticks: no live process answers to it,
    // exactly the shape a recycled pid presents.
    let stale_token = OwnershipToken {
        pid: stranger.id(),
        started_at: Some(0),
    };
    let mut process = OwnedProcess::with_token(stranger, stale_token);

    let filed = finalize_closed_run(&mut process, std::time::Duration::from_millis(300));
    assert_eq!(
        filed,
        FinalizationOutcome::StaleIdentityUntouched,
        "the run's record names the token's refusal, it never files silence"
    );
    assert_eq!(
        process.try_wait().expect("try_wait runs"),
        None,
        "the stranger is untouched: the close signaled nothing"
    );

    // The test's own cleanup, deliberately outside the token path.
    let mut child = process.into_inner();
    child.kill().expect("cleanup kill");
    child.wait().expect("cleanup reap");
}

/// The capture's exit block files the finalization outcome the gate
/// answered — this one-to-one mapping is the whole bridge, so the
/// stranger pin's named refusal is exactly what a capture would carry.
#[test]
fn the_stop_outcomes_map_onto_the_recorded_finalization_one_to_one() {
    assert_eq!(
        FinalizationOutcome::from(Stopped::Signaled),
        FinalizationOutcome::Signaled
    );
    assert_eq!(
        FinalizationOutcome::from(Stopped::AlreadyExited),
        FinalizationOutcome::AlreadyExited
    );
    assert_eq!(
        FinalizationOutcome::from(Stopped::StaleIdentityUntouched),
        FinalizationOutcome::StaleIdentityUntouched
    );
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

fn resize_at(at_ms: u64, cols: u16, rows: u16) -> ScriptedInteraction {
    ScriptedInteraction {
        at_ms,
        kind: calxgloss_types::InteractionKind::Resize { cols, rows },
    }
}

fn signal_at(at_ms: u64, signal: ScenarioSignal) -> ScriptedInteraction {
    ScriptedInteraction {
        at_ms,
        kind: calxgloss_types::InteractionKind::Signal { signal },
    }
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_scripted_scenario_run_acks_input_resize_and_signal_at_their_offsets() {
    // The interaction dimension drives the live terminal: each scripted
    // kind fires at its offset and stands acknowledged there. The terminal
    // dimension carries geometry content beside the bytes — the opening
    // geometry and the geometries the live terminal rendered after each
    // resize, read back off the running PTY, not echoed from the contract.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");
    let wine = warm_private_prefix(stage.path());

    let mut c = contract("scripted-run");
    c.idle_timeout_ms = 8_000;
    c.max_run_ms = 30_000;
    c.interactions = vec![
        input_at(1_500, "echo scripted-hello"),
        resize_at(2_500, 100, 30),
        signal_at(3_500, ScenarioSignal::Interrupt),
    ];

    let capture =
        capture_scenario(&program, &run_dir, &c, &wine, 1).expect("the scripted run files");
    let interaction = capture.interaction.expect("the interaction block stands");
    assert_eq!(
        interaction.acknowledged_at_ms,
        vec![1_500, 2_500, 3_500],
        "every scripted kind stands acknowledged at its offset"
    );

    let terminal = capture.terminal.expect("the terminal block stands");
    let text = visible_text(&terminal.chunks);
    assert!(
        text.contains("scripted-hello"),
        "the input interaction reached the fixture console: {text}"
    );
    assert_eq!(
        terminal.geometry,
        Some(TerminalGeometry { cols: 80, rows: 24 }),
        "the opening geometry is read off the live terminal"
    );
    assert_eq!(
        terminal.rendered_states,
        vec![TerminalGeometry {
            cols: 100,
            rows: 30
        }],
        "the resize landed on the live terminal, proven by read-back"
    );

    // The signal ended the run: the run closed as an exit on its own,
    // not by a window or finalization — the interrupt did its work.
    assert_eq!(
        capture.exit.expect("the exit block stands").disposition,
        ExitDisposition::Exited,
        "the signal ended the run"
    );
}

// ============================================================
// Declared secrets at the capture seam (P24.5, issue #406)
// ============================================================

#[test]
fn a_typed_secret_at_an_undeclared_offset_is_refused_naming_the_offset() {
    // A capture-time secret is only ever the typed form of a declared
    // placeholder: an offset carrying no byte-count placeholder is refused
    // naming that offset — before Wine is even consulted, since a secret
    // nobody declared is never typed anywhere.
    let dirs = tempfile::tempdir().expect("a workspace dir");
    let program = dirs.path().join("no-such.exe");
    write_file(dirs.path(), "no-such.exe", b"not even a PE");
    let wine = WineRunner::new(dirs.path()).with_wine_bin("calxgloss-no-such-wine");

    let mut c = contract("secret-refused");
    c.interactions = vec![ScriptedInteraction {
        at_ms: 1_000,
        kind: calxgloss_types::InteractionKind::Input {
            text: ScriptedInput::ByteCount { bytes: 6 },
        },
    }];
    let err = capture_scenario_with_secrets(
        &program,
        &dirs.path().join("run"),
        &c,
        &wine,
        &[TypedSecret {
            at_ms: 999,
            text: "twelve".to_string(),
        }],
        1,
    )
    .expect_err("a secret at an undeclared offset is refused before anything runs");
    let message = err.to_string();
    assert!(
        message.contains("999") && message.contains("byte-count placeholder"),
        "the refusal names the offset and what it missed: {message}"
    );
}

#[test]
fn a_typed_secret_whose_count_disagrees_with_the_placeholder_is_refused() {
    // The placeholder declares how many bytes stand at that offset; a
    // secret of any other length is refused naming both counts — the
    // capture never types what its contract did not say.
    let dirs = tempfile::tempdir().expect("a workspace dir");
    let program = dirs.path().join("no-such.exe");
    write_file(dirs.path(), "no-such.exe", b"not even a PE");
    let wine = WineRunner::new(dirs.path()).with_wine_bin("calxgloss-no-such-wine");

    let mut c = contract("secret-count");
    c.interactions = vec![ScriptedInteraction {
        at_ms: 1_000,
        kind: calxgloss_types::InteractionKind::Input {
            text: ScriptedInput::ByteCount { bytes: 6 },
        },
    }];
    let err = capture_scenario_with_secrets(
        &program,
        &dirs.path().join("run"),
        &c,
        &wine,
        &[TypedSecret {
            at_ms: 1_000,
            text: "sixteen byte text".to_string(),
        }],
        1,
    )
    .expect_err("a miscounted secret is refused before anything runs");
    let message = err.to_string();
    assert!(
        message.contains("1000") && message.contains("6") && message.contains("17"),
        "the refusal names the offset and both counts (declared 6, typed 17): {message}"
    );
}

#[test]
fn a_typed_secret_controlling_the_terminal_line_is_refused_naming_the_offset() {
    // A secret is typed as ONE line — its line ending belongs to the run.
    // Text carrying a line break or a control character would ride the
    // terminal as several inputs: the placeholder's single acknowledgement
    // would stand over one line while the rest typed on into the guest.
    // Such a secret is refused up front, naming its offset — even though
    // its byte count would match the placeholder.
    let dirs = tempfile::tempdir().expect("a workspace dir");
    let program = dirs.path().join("no-such.exe");
    write_file(dirs.path(), "no-such.exe", b"not even a PE");
    let wine = WineRunner::new(dirs.path()).with_wine_bin("calxgloss-no-such-wine");

    let mut c = contract("secret-line-break");
    c.interactions = vec![ScriptedInteraction {
        at_ms: 1_000,
        kind: calxgloss_types::InteractionKind::Input {
            text: ScriptedInput::ByteCount { bytes: 8 },
        },
    }];
    let err = capture_scenario_with_secrets(
        &program,
        &dirs.path().join("run"),
        &c,
        &wine,
        &[TypedSecret {
            at_ms: 1_000,
            text: "one\rtwo".to_string(),
        }],
        1,
    )
    .expect_err("a secret that would split into lines is refused before anything runs");
    let message = err.to_string();
    assert!(
        message.contains("1000") && message.contains("single line"),
        "the refusal names the offset and why the secret cannot type: {message}"
    );

    // The tab and other C0 controls steer the console's own editing, not
    // text: a secret containing one is refused the same way.
    let err = capture_scenario_with_secrets(
        &program,
        &dirs.path().join("run"),
        &c,
        &wine,
        &[TypedSecret {
            at_ms: 1_000,
            text: "one\ttwo".to_string(),
        }],
        1,
    )
    .expect_err("a secret carrying a control character is refused");
    assert!(
        err.to_string().contains("1000"),
        "the tab-carrying refusal names its offset: {err}"
    );
}

#[test]
fn two_typed_secrets_at_one_offset_are_refused_naming_the_offset() {
    // One placeholder per offset, one typed form each: two secrets at the
    // same offset is authorship confusion, and typing only one of them
    // after validating both would be a silent lie. Refused up front.
    let dirs = tempfile::tempdir().expect("a workspace dir");
    let program = dirs.path().join("no-such.exe");
    write_file(dirs.path(), "no-such.exe", b"not even a PE");
    let wine = WineRunner::new(dirs.path()).with_wine_bin("calxgloss-no-such-wine");

    let mut c = contract("secret-pair");
    c.interactions = vec![ScriptedInteraction {
        at_ms: 1_000,
        kind: calxgloss_types::InteractionKind::Input {
            text: ScriptedInput::ByteCount { bytes: 7 },
        },
    }];
    let err = capture_scenario_with_secrets(
        &program,
        &dirs.path().join("run"),
        &c,
        &wine,
        &[
            TypedSecret {
                at_ms: 1_000,
                text: "hunter2".to_string(),
            },
            TypedSecret {
                at_ms: 1_000,
                text: "pa$$word".to_string(),
            },
        ],
        1,
    )
    .expect_err("two secrets at one placeholder offset are refused");
    let message = err.to_string();
    assert!(
        message.contains("1000") && message.contains("only one secret"),
        "the refusal names the doubled offset: {message}"
    );
}

#[test]
#[ignore = "needs Wine and the mingw cross-toolchain"]
fn a_declared_secret_types_at_its_offset_and_stands_absent_from_the_record_bytes() {
    // The placeholder earns its keep here: the contract's filed form still
    // carries only the count, the capture types the declared secret at its
    // offset, and the fixture acknowledges it by count alone — the secret's
    // text appears nowhere in the capture's serialized raw bytes.
    let stage = tempfile::tempdir().expect("a staging dir");
    let run_dir = stage.path().join("run");
    std::fs::create_dir_all(&run_dir).expect("the run dir stands");
    let program = stage.path().join("fixture_console.exe");
    std::fs::copy(fixture_exe_path(), &program).expect("the fixture exe copies in");
    let wine = warm_private_prefix(stage.path());

    let mut c = contract("typed-secret");
    c.idle_timeout_ms = 8_000;
    c.max_run_ms = 30_000;
    c.interactions = vec![
        ScriptedInteraction {
            at_ms: 1_500,
            kind: calxgloss_types::InteractionKind::Input {
                text: ScriptedInput::ByteCount { bytes: 7 },
            },
        },
        input_at(2_500, "exit 0"),
    ];

    let capture = capture_scenario_with_secrets(
        &program,
        &run_dir,
        &c,
        &wine,
        &[TypedSecret {
            at_ms: 1_500,
            text: "hunter2".to_string(),
        }],
        1,
    )
    .expect("the declared secret rides the run");

    let interaction = capture
        .interaction
        .as_ref()
        .expect("the interaction block stands");
    assert_eq!(
        interaction.acknowledged_at_ms,
        vec![1_500, 2_500],
        "the placeholder earns its acknowledgement once its declared secret is typed"
    );

    let terminal = capture
        .terminal
        .as_ref()
        .expect("the terminal block stands");
    let text = visible_text(&terminal.chunks);
    assert!(
        text.contains("typed-bytes:7"),
        "the fixture acknowledges the secret by count, never by text: {text}"
    );

    // Absence proven at both seams that matter: no terminal chunk carries
    // the text, and the filed document's raw bytes never do.
    assert!(
        !terminal.chunks.join("").contains("hunter2"),
        "no terminal chunk carries the typed secret"
    );
    let document = serde_json::to_vec(&capture).expect("the capture serializes for filing");
    assert!(
        !document.windows("hunter2".len()).any(|w| w == b"hunter2"),
        "the typed secret appears nowhere in the capture document's raw bytes"
    );
}
