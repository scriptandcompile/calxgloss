//! The DLL generation walk end to end (the rebuilt pipeline suite).
//!
//! The fixture target DLL drives the whole generation sequence that needs
//! no live execution: the image opens, every named export gets an FFI
//! binding from its signature, a signature generates the stated test-input
//! suite, and baseline results file and read back whole under the
//! `re/baseline/` convention.
//!
//! Execution against the real DLL under Wine is owned by the `baseline`
//! suite (ignored wherever that toolchain is missing); this suite stops at
//! the door — everything here runs on any machine that builds the fixture.

use std::path::Path;

use calxgloss_testgen::{Machine, PeImage, TestGenerator};
use calxgloss_types::{BinaryIdentity, FunctionInfo, TestCase, TestResult};
use serde_json::json;

/// The fixture DLL opens as a 64-bit image and lists the four named
/// exports the fixture source ships, plus a nonzero image base.
#[test]
fn the_fixture_dll_opens_and_lists_its_named_exports() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let image = PeImage::parse(&fixture).expect("the fixture DLL parses");

    assert_eq!(image.machine(), Machine::X86_64);
    assert_ne!(
        image.image_base(),
        0,
        "the fixture is loaded at a real base"
    );

    let names: Vec<&str> = image.exports().iter().map(|e| e.name.as_str()).collect();
    for want in calxgloss_testfixtures::EXPORT_NAMES {
        assert!(
            names.contains(want),
            "{want} is an export of the fixture image, got {names:?}"
        );
    }
}

/// Every fixture export renders an FFI binding from its signature, and
/// two renders of one signature are byte-identical — the binding a run
/// files can never drift from the next run's.
#[test]
fn every_fixture_export_renders_a_byte_identical_binding_pair() {
    let generator = TestGenerator::new(Path::new("."));
    for export in calxgloss_testfixtures::EXPORT_NAMES {
        let signature = format!("int {export}(int param_1, int param_2)");
        let first = generator
            .generate_ffi_binding("fixture_target.dll", export, &signature)
            .expect("the binding generates");
        let second = generator
            .generate_ffi_binding("fixture_target.dll", export, &signature)
            .expect("the binding generates again");

        assert_eq!(
            first.code, second.code,
            "two renders of {export}'s binding are byte-identical"
        );
        assert_eq!(first.function, *export, "the binding names its function");
        assert!(
            first.code.contains("extern") && first.code.contains(export),
            "the binding is an extern declaration of {export}"
        );
    }
}

/// A two-integer signature generates the stated input suite (10–20 cases,
/// per the documented range) and repeats byte-identically; the input
/// suite's return slots stay empty for the baseline run to fill.
#[tokio::test]
async fn a_signature_generates_the_stated_input_suite_and_repeats_identically() {
    let generator = TestGenerator::new(Path::new("."));
    let signature = "int fixture_tick(int param_1, int param_2)";

    let first = generator
        .generate_test_inputs(signature, "", &[])
        .await
        .expect("inputs generate");
    let second = generator
        .generate_test_inputs(signature, "", &[])
        .await
        .expect("inputs generate again");

    assert!(
        (10..=20).contains(&first.len()),
        "the suite carries the documented 10–20 cases, got {}",
        first.len()
    );
    assert_eq!(
        json_strings(&first),
        json_strings(&second),
        "two input suites for one signature are identical"
    );
    for case in &first {
        assert!(
            case.expected_return.is_null() && case.expected_side_effects.is_empty(),
            "the generator leaves the baseline's answers to the run"
        );
    }
}

/// A [`FunctionInfo`] carries its own disassembly into the input
/// generation, and the walk succeeds whether the field is filled or empty.
#[tokio::test]
async fn function_info_drives_input_generation_from_its_own_fields() {
    let generator = TestGenerator::new(Path::new("."));

    for disassembly in ["", "00401000: cmp eax, 64h\n00401003: ja short 00401010"] {
        let info = FunctionInfo {
            name: "fixture_tick".into(),
            address: 0x1000,
            binary: BinaryIdentity::new("fixture_target.dll"),
            disassembly: disassembly.into(),
            decompiler_output: "{ return param_1 + param_2; }".into(),
            windows_apis: Vec::new(),
            call_graph: Vec::new(),
            disassembly_hints: Vec::new(),
        };
        let cases = generator
            .generate_test_inputs_from_function(&info)
            .await
            .expect("inputs generate from the function record");
        assert!(
            !cases.is_empty(),
            "the function record yields an input suite"
        );
    }
}

/// Baselines file under the `re/baseline/{binary}/{function}/baseline.json`
/// convention, read back exactly as saved, and a missing baseline fails.
#[test]
fn baselines_file_under_the_re_baseline_convention_and_read_back_whole() {
    let workspace = tempfile::tempdir().expect("temp workspace");
    let generator = TestGenerator::new(workspace.path());

    assert_eq!(
        generator.baseline_path("fixture_target.dll", "fixture_tick"),
        workspace
            .path()
            .join("re/baseline/fixture_target.dll/fixture_tick/baseline.json"),
        "the baseline path follows the re/baseline convention"
    );

    let saved = vec![
        result(json!([1, 2]), json!(3)),
        result(json!([i64::MIN, 0]), json!(i64::MIN)),
    ];
    generator
        .save_baseline("fixture_target.dll", "fixture_tick", &saved)
        .expect("the baseline files");
    assert!(
        workspace
            .path()
            .join("re/baseline/fixture_target.dll/fixture_tick/baseline.json")
            .is_file(),
        "the baseline stands at the conventional path"
    );

    let loaded = generator
        .load_baseline("fixture_target.dll", "fixture_tick")
        .expect("the baseline reads back");
    assert_eq!(
        json_strings_results(&loaded),
        json_strings_results(&saved),
        "the baseline reads back exactly as saved"
    );

    assert!(
        generator
            .load_baseline("fixture_target.dll", "fixture_unseen")
            .is_err(),
        "a never-filed baseline fails the load"
    );
}

/// The whole walk at once: open the fixture image, take a real export,
/// render its binding, generate its input suite, file the results as a
/// baseline, and read them back whole under the fixture's own binary name.
#[test]
fn the_full_walk_files_a_baseline_for_one_real_fixture_export() {
    let fixture = calxgloss_testfixtures::fixture_target_path().expect("fixture target");
    let image = PeImage::parse(&fixture).expect("the fixture DLL parses");
    let export = image
        .exports()
        .iter()
        .find(|e| e.name == "fixture_tick")
        .expect("fixture_tick is an export");

    let workspace = tempfile::tempdir().expect("temp workspace");
    let generator = TestGenerator::new(workspace.path());

    let signature = "int fixture_tick(int param_1, int param_2)";
    let binding = generator
        .generate_ffi_binding(
            calxgloss_testfixtures::TARGET_FILE_NAME,
            &export.name,
            signature,
        )
        .expect("the binding generates for the real export");
    assert!(binding.code.contains("fixture_tick"));

    let cases = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(generator.generate_test_inputs(signature, "", &[]))
        .expect("the input suite generates");

    let results: Vec<TestResult> = cases
        .into_iter()
        .map(|case| TestResult {
            test_case: case,
            actual_return: json!(0),
            actual_side_effects: Vec::new(),
            actual_api_calls: Vec::new(),
            passed: true,
            error: None,
        })
        .collect();

    generator
        .save_baseline("fixture_target.dll", "fixture_tick", &results)
        .expect("the baseline files");
    let loaded = generator
        .load_baseline("fixture_target.dll", "fixture_tick")
        .expect("the baseline reads back");
    assert_eq!(
        loaded.len(),
        results.len(),
        "the filed baseline carries the whole generated suite"
    );
    assert_eq!(
        json_strings_results(&loaded),
        json_strings_results(&results),
        "the whole walk's baseline reads back byte-for-byte in content"
    );
}

/// A minimal passing baseline result for `function` with given inputs and
/// observed return.
fn result(inputs: serde_json::Value, actual: serde_json::Value) -> TestResult {
    TestResult {
        test_case: TestCase {
            inputs,
            expected_return: serde_json::Value::Null,
            expected_side_effects: Vec::new(),
            expected_api_calls: Vec::new(),
        },
        actual_return: actual,
        actual_side_effects: Vec::new(),
        actual_api_calls: Vec::new(),
        passed: true,
        error: None,
    }
}

fn json_strings(cases: &[TestCase]) -> Vec<String> {
    cases
        .iter()
        .map(|c| serde_json::to_string(c).expect("a test case serializes"))
        .collect()
}

fn json_strings_results(results: &[TestResult]) -> Vec<String> {
    results
        .iter()
        .map(|r| serde_json::to_string(r).expect("a test result serializes"))
        .collect()
}
