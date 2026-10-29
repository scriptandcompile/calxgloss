//! The CLI's argument surface, tested at the process seam (the rebuilt
//! pipeline suite).
//!
//! These tests pin what clap promises before any engine starts: the help
//! text names every subcommand, every subcommand answers its own help,
//! the version line is exact, kebab-case names are enforced, and bad
//! invocations (unknown subcommand, missing required flag, wrong flag
//! value type) fail with clap's wording — no translation or scan work
//! ever begins. Behavior over real commands is owned by the
//! `scan_command` suite and friends.

use std::path::Path;
use std::process::Command;

/// Run the built CLI isolated from the ambient config, exactly as the
/// `scan_command` suite does: an empty config file per run, and the
/// target/workspace variables cleared.
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

/// Run `cmd` in `dir` and return (success, stdout, stderr).
fn run(cmd: &mut Command, dir: &Path) -> (bool, String, String) {
    let out = cmd.current_dir(dir).output().expect("the CLI ran");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The subcommand names the top-level help lists, parsed from the help
/// text itself so the suite follows the CLI wherever its roster goes.
fn listed_subcommands(help: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line.trim_end() == "Commands:" {
            in_commands = true;
            continue;
        }
        if in_commands {
            // Entries are indented two spaces with the command name as
            // the first token; the block ends at the first blank line.
            if line.trim().is_empty() {
                break;
            }
            if !line.starts_with("  ") || line.starts_with("   ") {
                continue;
            }
            if let Some(name) = line.split_whitespace().next() {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// The top-level help names the entry points by their kebab-case CLI
/// spelling — including the ones where a naive snake_case guess would be
/// wrong.
#[test]
fn the_top_level_help_names_the_entry_points_by_kebab_spelling() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, _) = run(cli(dir.path()).arg("--help"), dir.path());
    assert!(ok, "--help succeeds");
    for name in [
        "init",
        "doctor",
        "classify",
        "translate",
        "batch-translate",
        "global-state",
        "auto-shim",
        "dashboard",
        "serve",
        "live",
        "gc",
    ] {
        assert!(
            listed_subcommands(&stdout).iter().any(|n| n == name),
            "the help lists {name}"
        );
    }
    for name in &listed_subcommands(&stdout) {
        assert!(
            !name.contains('_'),
            "every listed subcommand is kebab-case, got {name}"
        );
    }
}

/// Every subcommand the help lists answers `--help` with usage naming
/// that subcommand — a renamed or vanished subcommand trips here first.
#[test]
fn every_listed_subcommand_answers_its_own_help() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (_, help, _) = run(cli(dir.path()).arg("--help"), dir.path());
    let names = listed_subcommands(&help);
    assert!(
        names.len() >= 30,
        "the roster carries the full command family, got {}",
        names.len()
    );
    for name in names {
        if name == "help" {
            continue; // clap's built-in help subcommand has its own shape
        }
        let (ok, stdout, _) = run(cli(dir.path()).args([&name, "--help"]), dir.path());
        assert!(ok, "`{name} --help` succeeds");
        assert!(
            stdout.contains(&format!("Usage: calxgloss-cli {name}")),
            "`{name} --help` names its own usage line"
        );
    }
}

/// The version line names the CLI and the package version — the release
/// identity a scan record reports against.
#[test]
fn the_version_line_names_the_cli_and_the_package_version() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, _) = run(cli(dir.path()).arg("--version"), dir.path());
    assert!(ok, "--version succeeds");
    assert_eq!(
        stdout.trim(),
        format!("calxgloss-cli {}", env!("CARGO_PKG_VERSION")),
        "the version line is exact"
    );
}

/// With no subcommand and no settings, the CLI fails by naming the
/// missing target dir and every way to supply it — never a panic and
/// never a bare usage dump.
#[test]
fn a_bare_run_fails_naming_the_missing_target_dir_and_its_sources() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, stdout, stderr) = run(&mut cli(dir.path()), dir.path());
    assert!(!ok, "a bare run does not succeed");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("target_dir is required"),
        "the refusal names the missing setting, got: {combined}"
    );
    for source in ["--target-dir", "calxgloss.toml", "CALXGLOSS_TARGET_DIR"] {
        assert!(
            combined.contains(source),
            "the refusal names {source} as a way to supply it"
        );
    }
}

/// A near-miss subcommand is refused by name and the closest real one is
/// suggested — a typo gets the user back on path.
#[test]
fn a_misspelled_subcommand_is_refused_with_the_closest_one_named() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(cli(dir.path()).arg("typesd"), dir.path());
    assert!(!ok, "a misspelled subcommand fails");
    assert!(
        stderr.contains("unrecognized subcommand 'typesd'"),
        "the refusal names what was rejected"
    );
    assert!(
        stderr.contains("typesdb"),
        "the closest real subcommand is suggested"
    );
}

/// Underscored spellings of kebab subcommands are refused, and clap's
/// suggestion points at the right one.
#[test]
fn underscores_are_refused_where_kebab_case_is_the_spelling() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(cli(dir.path()).arg("global_state"), dir.path());
    assert!(!ok, "global_state is not a subcommand");
    assert!(
        stderr.contains("unrecognized subcommand 'global_state'")
            && stderr.contains("'global-state'"),
        "the refusal suggests global-state"
    );
}

/// A scan command missing its required `--binary` fails at parse time,
/// naming the flag and its value placeholder.
#[test]
fn a_missing_required_flag_is_named_with_its_placeholder() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(cli(dir.path()).args(["typesdb", "--show"]), dir.path());
    assert!(!ok, "typesdb without --binary fails");
    assert!(
        stderr.contains("required arguments were not provided")
            && stderr.contains("--binary <BINARY>"),
        "the refusal names --binary <BINARY>, got: {stderr}"
    );
}

/// A non-numeric value for a numeric flag is rejected at parse time —
/// before any workspace is opened or any engine loads.
#[test]
fn a_wrong_typed_flag_value_is_rejected_at_parse_time() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(
        cli(dir.path()).args([
            "typeinfer",
            "--binary",
            "x.dll",
            "--confidence-floor",
            "high",
        ]),
        dir.path(),
    );
    assert!(!ok, "a non-numeric confidence floor fails");
    assert!(
        stderr.contains("invalid value 'high'") && stderr.contains("--confidence-floor"),
        "the refusal names the bad value and the flag, got: {stderr}"
    );
}

/// An unknown flag on a scan command is refused with clap's unexpected-
/// argument wording rather than being silently accepted.
#[test]
fn an_unknown_flag_is_refused_not_ignored() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, _, stderr) = run(
        cli(dir.path()).args(["typesdb", "--binary", "x.dll", "--not-a-flag"]),
        dir.path(),
    );
    assert!(!ok, "an unknown flag fails");
    assert!(
        stderr.contains("unexpected argument '--not-a-flag'"),
        "the refusal names the unknown flag, got: {stderr}"
    );
}

/// The `help` subcommand lists the same roster as `--help`, so either
/// entry point shows the same command family.
#[test]
fn the_help_subcommand_lists_the_same_roster_as_the_help_option() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, help_opt, _) = run(cli(dir.path()).arg("--help"), dir.path());
    let (ok2, help_cmd, _) = run(cli(dir.path()).arg("help"), dir.path());
    assert!(ok && ok2, "both help entry points succeed");
    assert_eq!(
        listed_subcommands(&help_opt),
        listed_subcommands(&help_cmd),
        "`help` and `--help` list the same roster"
    );
}

/// `help <command>` reaches the same usage as `<command> --help` — the
/// two spellings cannot drift apart.
#[test]
fn help_for_one_command_matches_its_own_help_flag() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (ok, flag_help, _) = run(cli(dir.path()).args(["typeinfer", "--help"]), dir.path());
    let (ok2, help_help, _) = run(cli(dir.path()).args(["help", "typeinfer"]), dir.path());
    assert!(ok && ok2, "both spellings succeed");
    for line in flag_help.lines() {
        if line.starts_with("Usage:") {
            assert!(
                help_help.contains(line.trim()),
                "`help typeinfer` carries the same usage line: {line}"
            );
            return;
        }
    }
    panic!("typeinfer --help printed no Usage: line");
}
