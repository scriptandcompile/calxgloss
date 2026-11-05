//! Process-level e2e for the `minidump` command (P23.7, issue #401):
//! the built CLI folds hand-assembled crash dumps over the fixture
//! target, prints the per-dump count report and the unclaimed-candidate
//! statement, lands the named records in the binary's unknown ledger,
//! and refuses a core file by name — no Wine in sight, because every
//! vector here is refused before the replay seam is ever reached.

use std::path::Path;
use std::process::Command;

use calxgloss_testfixtures::minidump::{ContextBytes, MinidumpBuilder};
use calxgloss_testgen::PeImage;

/// Run the built CLI isolated from the ambient config, as every engine
/// test does.
fn cli(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_calxgloss-cli"));
    let empty = dir.join("empty-config.toml");
    std::fs::write(&empty, "# empty: every setting falls back to its default")
        .expect("empty config written");
    cmd.env("CALXGLOSS_CONFIG", &empty);
    for key in ["CALXGLOSS_TARGET_DIR", "CALXGLOSS_WORKSPACE"] {
        cmd.env_remove(key);
    }
    cmd
}

fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn minidump_reports_refusals_per_dump_and_lands_named_records() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let pe = PeImage::parse(&fixture).expect("the fixture target parses");
    let dir = tempfile::tempdir().expect("temp dir");
    let ws = dir.path();
    std::fs::copy(&fixture, ws.join("fixture_target.dll")).expect("copy fixture into workspace");

    // A dump whose fault lands between export entries: the dump proves
    // a call happened somewhere, not which export received it, so the
    // lane states an unclaimed mapping candidate and folds nothing.
    let entry = pe.image_base() + u64::from(pe.export_rva_by_name("fixture_init").expect("export"));
    let near_miss = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            0x1000_0000,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(4096, ContextBytes::default(), 0x0012_0000, vec![])
        .exception_with_context(4096, 0xC000_0005, entry + 4, ContextBytes::default())
        .processor_architecture(9)
        .build();
    std::fs::write(ws.join("near-miss.dmp"), &near_miss).expect("dump written");

    // A dump that faults exactly on an export entry whose declared
    // first argument is a pointer, with the argument register naming
    // an address the dump never captured: the vector cannot be
    // materialized at replay, and the refusal carries the reason's
    // name (or, if Kuna's prototype renders the argument as a bare
    // width, the shape refusal names it instead — either way the
    // vector is refused and the replay seam never wakes).
    let ordered =
        pe.image_base() + u64::from(pe.export_rva_by_name("fixture_ordered").expect("export"));
    let exact_miss = MinidumpBuilder::new()
        .module(
            "C:\\Games\\fixture_target.dll",
            0x1000_0000,
            pe.size_of_image(),
            pe.time_date_stamp(),
        )
        .thread(
            4096,
            ContextBytes {
                rcx: 0xDEAD_0000,
                rsp: 0x0012_3040,
                ..Default::default()
            },
            0x0012_3000,
            vec![],
        )
        .exception_with_context(
            4096,
            0xC000_0005,
            0x1000_0000 + (ordered - pe.image_base()),
            ContextBytes {
                rcx: 0xDEAD_0000,
                rsp: 0x0012_3040,
                ..Default::default()
            },
        )
        .processor_architecture(9)
        .build();
    std::fs::write(ws.join("exact-miss.dmp"), &exact_miss).expect("dump written");

    let (ok, stdout, stderr) = run(
        cli(ws).args([
            "--target-dir",
            ".",
            "minidump",
            "--binary",
            "fixture_target.dll",
            "--dumps",
            "near-miss.dmp",
            "--dumps",
            "exact-miss.dmp",
        ]),
        ws,
    );
    assert!(ok, "minidump failed:\n{stdout}\n{stderr}");

    // Two dumps, two reports, in fold order: the unclaimed statement
    // comes with the first digest, before the second dump's report.
    let digests: Vec<usize> = stdout
        .lines()
        .enumerate()
        .filter(|(_, line)| line.starts_with("minidump: sha256:"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(digests.len(), 2, "{stdout}");
    let unclaimed = stdout
        .lines()
        .position(|line| line.contains("unclaimed mapping candidate"))
        .expect("the near-miss dump states its unclaimed candidate");
    assert!(
        unclaimed > digests[0] && unclaimed < digests[1],
        "the candidate belongs to the first dump, and the second dump's report follows: {stdout}"
    );

    // The count reports: nothing mined anywhere, the one claimed vector
    // refused with its reason named.
    assert!(stdout.contains("0 cases mined"), "{stdout}");
    assert!(stdout.contains("1 refusal named"), "{stdout}");

    // The named record lands in the binary's unknown ledger, named
    // for the dump digest and the faulting thread.
    let ledger = std::fs::read_to_string(ws.join("re/unknowns/fixture_target.dll.json"))
        .expect("the refusal lands in the unknown ledger");
    assert!(
        ledger.contains("capture_refused"),
        "the ledger names the kind"
    );
    assert!(
        ledger.contains("#4096"),
        "the ledger names the thread: {ledger}"
    );
    // Kuna's rendered prototype decides which refusal the vector earns:
    // a pointer-shaped first parameter makes the address unmaterializable,
    // a width-shaped one puts the pointer value out of signature shape.
    // Either way the vector is refused and the reason is named.
    let reason_named = ledger.contains("unmaterializable-pointer")
        || ledger.contains("argument-shape-not-in-signature");
    assert!(
        reason_named,
        "the ledger names the refusal reason: {ledger}"
    );

    // Nothing was replayed, so no baseline suite was filed anywhere.
    assert!(
        !ws.join("re/baseline").exists(),
        "an all-refused fold files no baseline suite"
    );
}

#[test]
fn minidump_refuses_a_core_file_by_name() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let dir = tempfile::tempdir().expect("temp dir");
    let ws = dir.path();
    std::fs::copy(&fixture, ws.join("fixture_target.dll")).expect("copy fixture into workspace");
    std::fs::write(ws.join("app-core"), b"\x7fELF\x02\x01\x01core").expect("core written");

    let (ok, _stdout, stderr) = run(
        cli(ws).args([
            "--target-dir",
            ".",
            "minidump",
            "--binary",
            "fixture_target.dll",
            "--dumps",
            "app-core",
        ]),
        ws,
    );
    assert!(!ok, "an ELF core must fail the run");
    assert!(stderr.contains("app-core"), "the file is named: {stderr}");
    assert!(
        stderr.contains("ELF core") && stderr.contains("out of scope"),
        "the refusal says why: {stderr}"
    );
}
