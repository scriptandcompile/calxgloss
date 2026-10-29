//! Source-level pins for the pipeline assembly contract (issue #328) and
//! the attempt-seam shape (issue #330, pin step #335).
//!
//! The compiler pins the crate boundary — the pipeline constructor and its
//! `with_*` setter surface are assembly-internal (`pub(crate)`), and so is
//! the whole attempt seam (`run_attempt`, `verify_and_record`, the verdict
//! and unit types) — so no code outside its own module can hand-build a
//! pass or drive an attempt around the loop. What the compiler cannot pin
//! is the fact *inside* the crate: across every crate's `src/` tree the
//! constructor is called in exactly one production module, the seam's own
//! `assembly.rs`, and every retry attempt goes through exactly one production
//! door — the loop in `retry/retry_loop.rs`. This suite pins those source
//! facts, so a fourth way to build a pass cannot reappear silently and the
//! deepened loop's bodies cannot silently re-inflate into the two ~450-line
//! inline attempt bodies the epic #330 deleted.
//!
//! These tests read the source tree and assert nothing about behavior;
//! what an assembled pass honors is pinned by the seam's behavior suite in
//! the sibling file `tests/assembly.rs`, and what the attempt seam does is
//! pinned by the loop's behavior suite in `retry/attempt.rs` and
//! `retry/retry_loop.rs`. Each retry pin below also names how it fails
//! against the pre-deepening shape — the pins are not vacuous.

use std::path::{Path, PathBuf};

/// The constructor's call-site spelling, composed so no file merely names
/// the contract (in a doc comment or an error message) can trip the pin.
const CONSTRUCTOR: &str = concat!("TranslationPipeline", "::new");

/// The one production module allowed to call it, relative to `crates/`.
const ASSEMBLY_MODULE: &str = "pipeline/calxgloss-translator/src/assembly.rs";

/// The loop — the one production module allowed to drive the attempt seam —
/// relative to `crates/`.
const RETRY_LOOP_MODULE: &str = "pipeline/calxgloss-translator/src/retry/retry_loop.rs";

/// The attempt seam — the one production module allowed to write the
/// per-attempt recording calls, relative to `crates/`.
const ATTEMPT_SEAM_MODULE: &str = "pipeline/calxgloss-translator/src/retry/attempt.rs";

/// The workspace's `crates/` directory, as seen from this crate's manifest.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("crates")
        .canonicalize()
        .expect("the workspace crates directory")
}

/// Every `.rs` file living under a `src` directory anywhere in `root`,
/// as paths relative to `root`. Integration tests (`tests/`), build
/// scripts, and benches are not production modules and stay out of the scan.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect(root, root, false, &mut out);
    out
}

fn collect(root: &Path, dir: &Path, in_src: bool, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read the source tree") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            let in_src = in_src || path.file_name().is_some_and(|name| name == "src");
            collect(root, &path, in_src, out);
        } else if in_src && path.extension().is_some_and(|ext| ext == "rs") {
            out.push(
                path.strip_prefix(root)
                    .expect("relative path")
                    .to_path_buf(),
            );
        }
    }
}

/// The production region of a file: everything before the first
/// `#[cfg(test)]` line — the repo's convention is that test modules sit at
/// the bottom of the file (`docs/standards.md`).
fn production_region(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .take_while(|line| !line.trim_start().starts_with("#[cfg(test)]"))
}

/// How often `needle` appears as code in the file's production region.
/// Comment lines never count: docs and prose name a function without
/// calling it. Definition and header lines (`fn needle…`, `struct needle…`,
/// `impl needle…`) never count either — a module defining or impl'ing a
/// name is not a module using it.
fn production_calls(text: &str, needle: &str) -> usize {
    production_region(text)
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter(|line| {
            let t = line.trim();
            !(t.contains(&format!("fn {needle}"))
                || t.contains(&format!("struct {needle}"))
                || t.contains(&format!("impl {needle}")))
        })
        .filter(|line| line.contains(needle))
        .count()
}

/// The production files where `needle` appears at least once as a call,
/// sorted for deterministic comparison.
fn files_calling(crates: &Path, files: &[PathBuf], needle: &str) -> Vec<String> {
    let mut hits: Vec<String> = files
        .iter()
        .filter(|file| {
            let text = std::fs::read_to_string(crates.join(file)).expect("read source file");
            production_calls(&text, needle) > 0
        })
        .map(|file| file.to_string_lossy().into_owned())
        .collect();
    hits.sort();
    hits
}

/// Whether a scan path lives in the retry tree — the `retry/` module and
/// its own `retry.rs` door.
fn in_retry_tree(file: &str) -> bool {
    file.starts_with("pipeline/calxgloss-translator/src/retry/")
        || file == "pipeline/calxgloss-translator/src/retry.rs"
}

#[test]
fn pipeline_constructor_is_called_in_exactly_one_production_module() {
    let crates = crates_dir();
    let files = source_files(&crates);
    assert!(
        files.len() > 100,
        "the source walk found only {} files — the scan itself is broken, \
         not the contract",
        files.len()
    );

    let hits: Vec<(String, usize)> = files
        .iter()
        .map(|file| {
            let text = std::fs::read_to_string(crates.join(file)).expect("read source file");
            (
                file.to_string_lossy().into_owned(),
                production_calls(&text, CONSTRUCTOR),
            )
        })
        .filter(|(_, calls)| *calls > 0)
        .collect();

    assert_eq!(
        hits,
        vec![(ASSEMBLY_MODULE.to_string(), 1)],
        "`{CONSTRUCTOR}` must be called in exactly one production module — \
         the assembly seam — so every pass provably arrives through assembly; \
         a second caller means a hand-built pass rejoined the tree (issue #328)"
    );
}

// ==========================================================================
// The attempt seam (issue #330) — the loop is the one door, the seam is the
// one body, and no attempt record or prompt builder lives outside them.
// ==========================================================================

/// Every attempt of a unit goes through the seam in `retry/attempt.rs`, and only
/// the loop in `retry/retry_loop.rs` may put it through: `run_attempt(` and
/// `verify_and_record(` are `pub(crate)`, so outside the crate nothing can
/// call them at all; inside, a second caller would be a second loop — or a
/// bypass of the one loop — driving attempts around the recorded door.
///
/// Pre-deepening this pin fails by construction: the seam did not exist
/// yet, so zero files call it. A third caller today trips the equality.
#[test]
fn only_the_retry_loop_rides_the_attempt_seam() {
    let crates = crates_dir();
    let files = source_files(&crates);

    for needle in [
        concat!("run_", "attempt("),
        concat!("verify_and_", "record("),
    ] {
        let hits = files_calling(&crates, &files, needle);
        assert_eq!(
            hits,
            vec![RETRY_LOOP_MODULE.to_string()],
            "`{needle}` must be called in exactly one production module — the \
             retry loop — so every attempt provably goes through the seam's \
             recording and reporting tail (issue #330)"
        );
    }
}

/// The per-attempt recording calls — the token-usage log and the
/// prompt-variant experiment log — appear once, inside the seam, and
/// called from nowhere else: an attempt that skipped the seam would also
/// skip the experiment and token records the operator reads.
///
/// Pre-deepening this pin fails: both calls were made in the retry
/// loop's own body, not in `retry/attempt.rs`, so the equality names
/// the wrong module.
#[test]
fn the_attempt_seam_is_the_only_caller_of_the_per_attempt_log_sinks() {
    let crates = crates_dir();
    let files = source_files(&crates);

    for needle in [
        concat!("log_token_", "usage("),
        concat!("log_prompt_variant_", "experiment("),
    ] {
        let hits = files_calling(&crates, &files, needle);
        assert_eq!(
            hits,
            vec![ATTEMPT_SEAM_MODULE.to_string()],
            "`{needle}` must be called from exactly one production module — \
             the attempt seam — so no recorded attempt can dodge the token or \
             experiment log (issue #330)"
        );
    }
}

/// Every `TranslationAttempt` is constructed, and every attempt enters a
/// `RetryResult`, inside the retry tree — and inside it, only where an
/// attempt is born: the seam records everything the chain put in front of
/// the verifier, and the loop keeps exactly the two bookkeeping records of
/// attempts that never reached an LLM at all (the Default-skip entry and
/// the tier-escalation-build-failure entry). A construction site anywhere
/// else — `batch.rs`, `pipeline.rs`, a future module — would be a hand-
/// stamped attempt joining the chain outside the seam.
///
/// (The #335 wording "one production module builds a `RetryResult`"
/// refines to this chain invariant: `RetryResult::new()` itself is also
/// called as an empty placeholder by `batch.rs` and `pipeline.rs` for
/// skipped and refused units that never enter a chain — bookkeeping the
/// pin would only be encoding incidentally. What must not move is where
/// attempts come from.)
///
/// Pre-deepening this pin fails: both needles were called/constructed in
/// the retry loop alone (no `retry/attempt.rs`), so the exact pair names
/// the wrong shape.
#[test]
fn attempts_are_born_only_at_the_seam_and_the_loops_two_bookkeeping_arms() {
    let crates = crates_dir();
    let files = source_files(&crates);

    let expected = vec![
        ATTEMPT_SEAM_MODULE.to_string(),
        RETRY_LOOP_MODULE.to_string(),
    ];
    for needle in [
        concat!("add_", "attempt("),
        concat!("Translation", "Attempt {"),
    ] {
        let hits = files_calling(&crates, &files, needle);
        assert_eq!(
            hits, expected,
            "`{needle}` must appear as code in exactly the seam and the loop's \
             two never-reached-the-LLM bookkeeping arms — an attempt constructed \
             elsewhere is a verdict stamped outside the verifier (issue #330)"
        );
        assert!(
            hits.iter().all(|file| in_retry_tree(file)),
            "`{needle}` escaped the retry tree: {hits:?}"
        );
    }
}

/// The strategy prompt builders are driven only through the retry tree's
/// adapters and the closed dispatch in `retry.rs` — no production module
/// outside the tree assembles a fix prompt by hand. (Public re-exports
/// stay for the template test suite; nothing in any crate's production
/// region reaches past the door. `calxgloss-prompts`' own build.rs is the
/// builders' defining crate — its wrappers delegating to their
/// with-context siblings are definitions, not consumers, and sit out.)
///
/// Pre-deepening this pin fails vacuity in the other direction: the loop
/// matched over the strategies and called each builder inline from
/// `retry_loop.rs` — inside the tree, so this pin is not what pinned the
/// dispatch step; it pins the shape against future bypass, and #333's
/// byte-identity pins did the moving-time work.
#[test]
fn no_production_module_outside_the_retry_tree_drives_the_prompt_builders() {
    const BUILDERS: [&str; 8] = [
        "build_compile_fix_prompt(",
        "build_failure_informed_compile_fix_prompt(",
        "build_test_fix_prompt(",
        "build_failure_informed_test_fix_prompt(",
        "build_edge_case_fix_prompt(",
        "build_failure_informed_edge_case_fix_prompt(",
        "build_escalate_prompt_with_context(",
        "build_failure_informed_escalate_prompt(",
    ];

    let crates = crates_dir();
    let files = source_files(&crates);
    let outside: Vec<&PathBuf> = files
        .iter()
        .filter(|file| {
            let file = file.to_string_lossy();
            !in_retry_tree(&file) && !file.starts_with("integrations/calxgloss-prompts/src/")
        })
        .collect();

    for name in BUILDERS {
        let offenders: Vec<String> = outside
            .iter()
            .filter(|file| {
                let text = std::fs::read_to_string(crates.join(file)).expect("read source file");
                production_calls(&text, name) > 0
            })
            .map(|file| file.to_string_lossy().into_owned())
            .collect();
        assert!(
            offenders.is_empty(),
            "`{name}` is called by production modules outside the retry tree — \
             the closed dispatch in `retry.rs` is the retry context's single \
             door to the builders (issue #330): {offenders:?}"
        );
    }
}

/// The deepening's shape, locked at the line level: the retry loop's
/// production body is policy only — selection, gates, and stop routing —
/// and fits the budget. Before the seam, the two inline attempt bodies
/// spanned roughly 900 production lines on their own and the file's
/// production region ran well past 1,200; the budget leaves room for
/// ordinary policy growth and fails hard if a ~450-line attempt body is
/// ever moved back into the loop (issue #330; measured 493 at write-time).
#[test]
fn the_retry_loop_body_stays_policy_only_within_budget() {
    let crates = crates_dir();
    let text =
        std::fs::read_to_string(crates.join(RETRY_LOOP_MODULE)).expect("read the retry loop");
    let production_lines = production_region(&text).count();
    assert!(
        production_lines <= 600,
        "the retry loop's production region grew to {production_lines} lines — \
         the inline attempt bodies the seam replaced spanned ~900 on their own; \
         a body this big in the loop means it re-inflated past policy (issue #330)"
    );
}

/// The public surface the epic was forbidden to move: everything outside
/// the crate used from `retry::` before the epic still resolves from out
/// here — an integration test, seeing only the crate's `pub` surface. The
/// loop's entry keeps taking `(Translation, &RetryLoopCtx)`; the config,
/// result, attempt, strategy types, the builders and the detection helper
/// all stay re-exported exactly as before. Meanwhile the seam itself —
/// `run_attempt`, `verify_and_record`, `AttemptOutcome`, `AttemptUnit` —
/// is `pub(crate)` and stays invisible from this file (the compiler pins
/// that: this test would not compile if the seam leaked).
#[test]
fn the_public_retry_surface_compiles_from_outside_the_crate() {
    use calxgloss_translator::retry::{
        AUTO_STRATEGY_CYCLE, EscalatePromptCtx, FixPromptCtx, RetryConfig, RetryLoopCtx,
        RetryResult, RetryStrategy, TranslationAttempt, build_compile_fix_prompt,
        build_edge_case_fix_prompt, build_escalate_prompt_with_context,
        build_failure_informed_compile_fix_prompt, build_failure_informed_edge_case_fix_prompt,
        build_failure_informed_escalate_prompt, build_failure_informed_test_fix_prompt,
        build_test_fix_prompt, is_edge_case_failure, log_prompt_variant_experiment,
        try_translate_with_retry,
    };

    // The config is built from out here with its public fields, exactly
    // as every production caller builds it.
    let config = RetryConfig {
        max_attempts: 3,
        retry_strategy: RetryStrategy::CompileFix,
        escalate_on_failure: true,
        max_context_tier: None,
    };
    assert_eq!(config.max_attempts, 3);

    // Take the entry and every re-exported name as values — the paths
    // resolve and the items keep their shapes.
    let _entry = try_translate_with_retry;
    let _builders = (
        build_compile_fix_prompt,
        build_failure_informed_compile_fix_prompt,
        build_test_fix_prompt,
        build_failure_informed_test_fix_prompt,
        build_edge_case_fix_prompt,
        build_failure_informed_edge_case_fix_prompt,
        build_escalate_prompt_with_context,
        build_failure_informed_escalate_prompt,
    );
    let _extras = (is_edge_case_failure, log_prompt_variant_experiment);
    let _types = |_: &RetryLoopCtx<'_>,
                  _: &FixPromptCtx,
                  _: &EscalatePromptCtx,
                  _: &TranslationAttempt,
                  _: &RetryResult| {};
    assert!(!AUTO_STRATEGY_CYCLE.is_empty());
}
