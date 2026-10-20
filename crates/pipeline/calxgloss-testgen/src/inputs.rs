//! Test input generation for function baseline testing.
//!
//! This module provides functionality to generate diverse test inputs based on
//! function signatures and disassembly analysis. Generated inputs cover boundary
//! values, typical values, and edge cases identified from the disassembly.
//!
//! # Generation Strategy
//!
//! Test inputs are generated using the following strategy:
//!
//! 1. **Signature-based generation** — parse parameter types and generate
//!    boundary values (min/max/zero) for each type
//! 2. **Disassembly-based generation** — analyze disassembly for edge cases
//!    like boundary checks (`cmp eax, 256`), null checks (`test eax, eax`),
//!    and negative checks
//! 3. **Branch-inventory generation** — one baseline case per branch target
//!    from the control-flow scan's branch inventory: the equality value for
//!    equality guards, the immediate ±1 for relational guards, a null/zero
//!    probe for null-check guards and shape-only readings, and one case
//!    value per switch arm; parameters the condition does not involve hold
//!    typical values
//! 4. **Combination** — merge all sets and deduplicate to produce the final
//!    test case list, capped per function with the lowest-confidence branch
//!    cases dropped first

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use calxgloss_controlflow::types::{BranchSite, GuardedTarget};
use calxgloss_types::TestCase;
use serde_json::json;
use tracing::{debug, instrument};

use crate::ffi::{ParameterTypeInfo, ParsedSignature};

/// A source of edge cases for test input generation.
///
/// Edge cases may come from disassembly patterns or be derived from
/// type information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCaseSource {
    /// Zero value check (e.g., `cmp eax, 0` or `test eax, eax`).
    Zero,

    /// Negative one check.
    NegativeOne,

    /// Minimum i32 value.
    MinI32,

    /// Maximum i32 value.
    MaxI32,

    /// Minimum u32 value (zero).
    MinU32,

    /// Maximum u32 value.
    MaxU32,

    /// Null pointer check.
    NullPointer,

    /// Empty string check.
    EmptyString,

    /// Maximum string length.
    MaxStringLength,

    /// Minimum float value.
    MinFloat,

    /// Maximum float value.
    MaxFloat,

    /// NaN value.
    NaN,

    /// A pattern extracted from disassembly.
    DisassemblyPattern(String),
}

/// Edge cases extracted from disassembly analysis.
///
/// Parses disassembly for common patterns that indicate boundary checks
/// and edge cases the function handles.
#[derive(Debug, Clone, Default)]
pub struct DisassemblyEdgeCases {
    /// Values compared against in boundary checks (e.g., `cmp eax, 256`).
    pub boundary_checks: Vec<i64>,

    /// Values compared against for negative range checks.
    pub negative_checks: Vec<i64>,

    /// Zero comparison targets found.
    pub zero_checks: HashSet<String>,

    /// Maximum value checks found.
    pub max_value_checks: Vec<i64>,
}

impl DisassemblyEdgeCases {
    /// Extract edge cases from disassembly text.
    ///
    /// Analyzes the disassembly for common patterns:
    /// - `cmp reg, N` / `test reg, N` — immediate value comparisons
    /// - `cmp reg, 0` — zero checks
    /// - `cmp reg, -1` — negative one checks
    /// - `cmp reg, 256` / `cmp reg, 65536` — common boundary values
    ///
    /// Both spellings read: the lowercase objdump-style spelling the
    /// retired bridge used to serve (`cmp eax, 256`) and the engine's
    /// uppercase SLEIGH listing with `0x` hex immediates (`CMP EAX,0x64`).
    ///
    /// # Arguments
    ///
    /// * `disassembly` — Raw disassembly text to analyze.
    ///
    /// # Returns
    ///
    /// A [`DisassemblyEdgeCases`] struct populated with found edge cases.
    #[instrument(skip(disassembly))]
    pub fn from_disassembly(disassembly: &str) -> Self {
        debug!(
            length = disassembly.len(),
            "Extracting edge cases from disassembly"
        );

        let mut cases = Self::default();

        for line in disassembly.lines() {
            let line = line.trim();
            Self::extract_cmp_values(line, &mut cases);
            Self::extract_test_values(line, &mut cases);
            Self::extract_jump_targets(line, &mut cases);
        }

        // Deduplicate
        cases.zero_checks = std::mem::take(&mut cases.zero_checks);

        debug!(
            boundaries = cases.boundary_checks.len(),
            negatives = cases.negative_checks.len(),
            zeros = cases.zero_checks.len(),
            max_values = cases.max_value_checks.len(),
            "Extracted disassembly edge cases"
        );

        cases
    }

    /// Extract values from `cmp` instructions.
    fn extract_cmp_values(line: &str, cases: &mut Self) {
        // Match patterns like "cmp eax, 256" or "cmp ecx, -1", and Kuna's
        // SLEIGH-style spelling "CMP EAX,0x64": the mnemonic case and the
        // `0x` hex immediate are dialect, the compared value is the signal.
        if let Some(cap) = regex::Regex::new(r"(?i)cmp\s+\w+,\s*(0x[0-9a-f]+|-?\d+)")
            .ok()
            .and_then(|r| r.captures(line))
            && let Some(val_str) = cap.get(1)
            && let Some(val) = parse_immediate(val_str.as_str())
        {
            match val {
                0 => {
                    cases.zero_checks.insert("cmp_zero".to_string());
                }
                -1 => {
                    cases.negative_checks.push(val);
                }
                1..=1000 => {
                    // Likely a boundary check for small values
                    if !cases.boundary_checks.contains(&val) {
                        cases.boundary_checks.push(val);
                    }
                }
                _ => {
                    // Large values might be addresses or flags
                    if !cases.boundary_checks.contains(&val)
                        && !cases.max_value_checks.contains(&val)
                    {
                        cases.max_value_checks.push(val);
                    }
                }
            }
        }
    }

    fn extract_test_values(line: &str, cases: &mut Self) {
        // Match patterns like "test eax, eax" or "test ecx, 0FFh", and
        // Kuna's SLEIGH-style "TEST EAX,0x0F".
        if let Some(cap) = regex::Regex::new(r"(?i)test\s+(\w+),\s*(\w+)")
            .ok()
            .and_then(|r| r.captures(line))
        {
            let operand2 = cap.get(2).map(|m| m.as_str()).unwrap_or("");
            if operand2 == "0" || operand2 == "0h" || operand2 == "0H" || operand2 == "0x0" {
                cases.zero_checks.insert("test_zero".to_string());
            } else if operand2.ends_with('h') || operand2.ends_with('H') {
                // Hexadecimal value
                if let Ok(val) = i64::from_str_radix(&operand2[..operand2.len() - 1], 16) {
                    if val == 0 {
                        cases.zero_checks.insert("test_hex_zero".to_string());
                    } else if val > 0 && val <= 1000 && !cases.boundary_checks.contains(&val) {
                        cases.boundary_checks.push(val);
                    }
                }
            } else if let Some(val) = parse_immediate(operand2) {
                // `0x`-prefixed hex immediate (Kuna's spelling).
                if val > 0 && val <= 1000 && !cases.boundary_checks.contains(&val) {
                    cases.boundary_checks.push(val);
                }
            }
        }
    }

    /// Extract jump targets from conditional jump instructions.
    fn extract_jump_targets(line: &str, cases: &mut Self) {
        // Match patterns like "je zero_handler" or "jz null_exit"
        if let Some(cap) = regex::Regex::new(r"j(e|z|nz|l|le|g|ge|be|ae|c|nc)\s+(\w+)")
            .ok()
            .and_then(|r| r.captures(line))
            && let Some(target) = cap.get(2)
        {
            let target_lower = target.as_str().to_lowercase();
            if target_lower.contains("zero")
                || target_lower.contains("null")
                || target_lower.contains("empty")
                || target_lower.contains("neg")
                || target_lower.contains("underflow")
                || target_lower.contains("overflow")
            {
                cases
                    .zero_checks
                    .insert(format!("jump_{}", target.as_str()));
            }
        }
    }

    /// Get all unique boundary values for test generation.
    pub fn get_boundary_values(&self) -> Vec<i64> {
        let mut values: Vec<i64> = self.boundary_checks.clone();
        values.extend(self.negative_checks.clone());
        values.extend(self.max_value_checks.clone());
        values.sort();
        values.dedup();
        values
    }
}

/// Parse an immediate operand in either dialect: `0x`-prefixed hex (Kuna's
/// SLEIGH spelling, e.g. `0x64`) or plain decimal (e.g. `256`, `-1`).
fn parse_immediate(text: &str) -> Option<i64> {
    let (sign, digits) = match text.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1, text),
    };
    match digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        Some(hex) => i64::from_str_radix(hex, 16).ok().map(|v| sign * v),
        None => text.parse::<i64>().ok(),
    }
}

/// Generate diverse test inputs for a function.
///
/// This is the main entry point for test input generation. It combines
/// signature-based and disassembly-based test generation to produce
/// comprehensive test coverage, and grows one branch-targeted case per
/// branch target from the control-flow scan's branch inventory so the
/// suite pins each branch the decompiled body reveals, not just the
/// happy path.
///
/// # Arguments
///
/// * `signature` — The function signature string.
/// * `disassembly` — Raw disassembly for edge case detection.
/// * `branch_inventory` — The target function's branch-site records from
///   the control-flow scan, in body order (the caller hands the records
///   for this function; the generator does not filter by name). An empty
///   inventory means today's behavior exactly: the output is byte-identical
///   to what the same signature and disassembly produced before the seam
///   grew this parameter.
///
/// # Returns
///
/// A vector of [`TestCase`] structs with populated inputs. The expected
/// return values and side effects are left empty (null/empty) since they
/// must be captured from baseline execution.
///
/// Branch-targeted cases ride after the existing suite, deduplicated
/// against it; the suite is capped at [`MAX_TEST_CASES_PER_FUNCTION`] per
/// function, and when the cap bites the lowest-confidence branch cases
/// drop first — ties break toward the later site in body order — so the
/// boundary cases mined from the signature and disassembly always survive.
///
/// # Example
///
/// ```
/// use calxgloss_testgen::generate_test_inputs;
///
/// let sig = "int __stdcall DrawSprite(int x, int y, unsigned int texture_index)";
/// let disassembly = "cmp eax, 0\nje null_handler\ncmp ecx, 256\nja out_of_bounds";
///
/// let tests = generate_test_inputs(sig, disassembly, &[]).unwrap();
/// assert!(!tests.is_empty());
/// ```
#[instrument(skip(signature, disassembly, branch_inventory))]
pub fn generate_test_inputs(
    signature: &str,
    disassembly: &str,
    branch_inventory: &[BranchSite],
) -> Result<Vec<TestCase>> {
    let mut test_cases = Vec::new();

    // Parse signature if available
    let parsed = if !signature.is_empty() {
        crate::parse_signature(signature).ok()
    } else {
        None
    };

    // Extract disassembly edge cases
    let edge_cases = DisassemblyEdgeCases::from_disassembly(disassembly);

    if let Some(ref parsed) = parsed {
        // Generate signature-based test cases
        let sig_tests = generate_signature_tests(parsed, &edge_cases);
        test_cases.extend(sig_tests);

        // Generate disassembly-guided test cases
        let dis_tests = generate_disassembly_tests(parsed, &edge_cases);
        test_cases.extend(dis_tests);
    } else if !disassembly.is_empty() {
        // No signature, generate generic tests based on disassembly patterns
        let generic_tests = generate_generic_tests(&edge_cases);
        test_cases.extend(generic_tests);
    }

    // Ensure we have a reasonable minimum number of tests
    if test_cases.len() < 3 {
        test_cases.extend(generate_generic_tests(&edge_cases));
    }

    // Deduplicate test inputs
    test_cases = deduplicate_tests(test_cases);

    // Branch-targeted cases ride after the deduplicated suite so an empty
    // inventory leaves today's output byte-identical. They dedup against
    // the boundary cases first — a branch case duplicating a case the
    // suite already holds never consumes cap room — and when the cap
    // bites the lowest-confidence branch cases drop first.
    if !branch_inventory.is_empty() {
        let existing: HashSet<String> = test_cases
            .iter()
            .map(|t| t.inputs.to_string())
            .collect();
        let mut branch: Vec<BranchCase> = generate_branch_tests(parsed.as_ref(), branch_inventory)
            .into_iter()
            .filter(|case| !existing.contains(&case.test.inputs.to_string()))
            .collect();
        let room = MAX_TEST_CASES_PER_FUNCTION.saturating_sub(test_cases.len());
        if branch.len() > room {
            branch.sort_by(|a, b| {
                b.confidence
                    .cmp(&a.confidence)
                    .then_with(|| a.order.cmp(&b.order))
            });
            branch.truncate(room);
            branch.sort_by_key(|case| case.order);
        }
        test_cases.extend(branch.into_iter().map(|case| case.test));
    }

    debug!(
        count = test_cases.len(),
        inventory = branch_inventory.len(),
        "Generated test inputs"
    );

    Ok(test_cases)
}

/// Generate test inputs based on the function signature.
fn generate_signature_tests(
    parsed: &ParsedSignature,
    edge_cases: &DisassemblyEdgeCases,
) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let params = &parsed.parameters;

    if params.is_empty() {
        // No parameters, just one test with empty inputs
        tests.push(TestCase {
            inputs: json!({}),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
        return tests;
    }

    // Generate one test for each combination of boundary values
    let param_boundaries: Vec<Vec<serde_json::Value>> = params
        .iter()
        .map(|p| param_boundary_values(p, edge_cases))
        .collect();

    // Generate individual parameter boundary tests
    for (i, param_boundaries_item) in param_boundaries.iter().enumerate() {
        for boundary_value in param_boundaries_item {
            let mut inputs = serde_json::Map::new();
            for (j, param) in params.iter().enumerate() {
                if j == i {
                    inputs.insert(format!("param_{}", j), boundary_value.clone());
                } else {
                    // Use default value for other params
                    inputs.insert(format!("param_{}", j), param_default_value(param));
                }
            }
            tests.push(TestCase {
                inputs: json!(inputs),
                expected_return: json!(null),
                expected_side_effects: Vec::new(),
            });
        }
    }

    // Generate a "zero" test if the function has integer parameters
    if has_integer_params(params) {
        let mut inputs = serde_json::Map::new();
        for (i, param) in params.iter().enumerate() {
            inputs.insert(format!("param_{}", i), param_zero_value(param));
        }
        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    // Generate a "typical" test with reasonable default values
    let mut inputs = serde_json::Map::new();
    for (i, param) in params.iter().enumerate() {
        inputs.insert(format!("param_{}", i), param_typical_value(param));
    }
    tests.push(TestCase {
        inputs: json!(inputs),
        expected_return: json!(null),
        expected_side_effects: Vec::new(),
    });

    // Generate a "max value" test for the first integer param
    if let Some(first_int_idx) = params.iter().position(|p| is_integer_type(&p.r#type)) {
        let mut inputs = serde_json::Map::new();
        for (j, param) in params.iter().enumerate() {
            if j == first_int_idx {
                inputs.insert(format!("param_{}", j), param_max_value(param));
            } else {
                inputs.insert(format!("param_{}", j), param_default_value(param));
            }
        }
        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// Generate test inputs guided by disassembly edge cases.
fn generate_disassembly_tests(
    parsed: &ParsedSignature,
    edge_cases: &DisassemblyEdgeCases,
) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let params = &parsed.parameters;

    if params.is_empty() {
        return tests;
    }

    // Use boundary values from disassembly
    let boundary_values = edge_cases.get_boundary_values();

    for boundary in &boundary_values {
        let mut inputs = serde_json::Map::new();
        // Apply boundary to first integer parameter
        for (i, param) in params.iter().enumerate() {
            if is_integer_type(&param.r#type) {
                inputs.insert(
                    format!("param_{}", i),
                    json!(if param.is_signed {
                        *boundary
                    } else {
                        (*boundary as u64).min(u32::MAX as u64) as i64
                    }),
                );
                break;
            }
        }

        // Fill remaining params with defaults
        for (i, param) in params.iter().enumerate() {
            if !inputs.contains_key(&format!("param_{}", i)) {
                inputs.insert(format!("param_{}", i), param_default_value(param));
            }
        }

        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// Generate generic test inputs when no signature is available.
fn generate_generic_tests(edge_cases: &DisassemblyEdgeCases) -> Vec<TestCase> {
    let mut tests = Vec::new();
    let boundary_values = edge_cases.get_boundary_values();

    // Generate a few generic integer test inputs
    let generic_values = vec![0i64, -1, 1, 100, 1000];
    let all_values: Vec<i64> = boundary_values.into_iter().chain(generic_values).collect();

    for value in all_values {
        let mut inputs = serde_json::Map::new();
        inputs.insert("param_0".to_string(), json!(value));
        inputs.insert("param_1".to_string(), json!(0));
        inputs.insert("param_2".to_string(), json!(0));

        tests.push(TestCase {
            inputs: json!(inputs),
            expected_return: json!(null),
            expected_side_effects: Vec::new(),
        });
    }

    tests
}

/// The per-function ceiling on generated test cases. A branch-heavy body
/// cannot explode the baseline suite: when the cap bites, branch-targeted
/// cases drop — lowest confidence first — before any boundary case mined
/// from the signature or disassembly is touched.
const MAX_TEST_CASES_PER_FUNCTION: usize = 40;

/// A branch-targeted case tagged with the confidence of the record that
/// produced it and the site's position in body order — the two facts the
/// per-function cap uses to decide which cases drop first.
struct BranchCase {
    test: TestCase,
    confidence: u8,
    order: usize,
}

/// The boundary value a branch probe feeds in: a parsed immediate, or the
/// null/zero probe a record that read no constant falls back to.
#[derive(Debug, Clone, Copy)]
enum Probe {
    /// An integer boundary value — decimal, `0x` hex, or a char literal's code.
    Value(i64),
    /// A float boundary value.
    Float(f64),
    /// Zero/null for the parameters the condition names.
    Zero,
}

/// Generate one baseline case per branch target from the scan's branch
/// inventory, in body order:
///
/// - an equality guard (`==`/`!=`) yields its equality value;
/// - a relational guard (`<` `<=` `>` `>=`) yields the immediate ±1 — both
///   sides of the boundary, so an off-by-one mistranslation diverges on
///   one of them (loop-exit boundaries included: whichever side the exit
///   sits on, the pair straddles it);
/// - a null-check guard (an equality guard against zero) and a shape-only
///   reading that names no predicate yield a null/zero probe and nothing
///   else — a record that read no constant fabricates no boundary;
/// - a switch arm yields its case value; a named case constant that is not
///   a literal degrades to the null/zero probe rather than inventing a
///   value for the name.
///
/// Parameters the condition does not involve hold typical values, and the
/// probe respects the parameter types the signature declares so the Wine
/// harness can encode it — a probe outside the parameter's representable
/// range drops that case instead of producing an unencodable input.
fn generate_branch_tests(
    parsed: Option<&ParsedSignature>,
    sites: &[BranchSite],
) -> Vec<BranchCase> {
    let mut cases: Vec<BranchCase> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (order, site) in sites.iter().enumerate() {
        let confidence = u8::from(site.confidence);
        for probe in branch_probes(site) {
            let test = match parsed {
                Some(parsed) => branch_case_for_signature(parsed, site, &probe),
                None => branch_case_generic(site, &probe),
            };
            let Some(test) = test else { continue };
            let key = test.inputs.to_string();
            if let Some(&first) = seen.get(&key) {
                // Two sites probing the same input set: keep the copy
                // backed by the more confident record so the cap drops
                // the right one when it bites.
                if confidence > cases[first].confidence {
                    cases[first].confidence = confidence;
                }
                continue;
            }
            seen.insert(key, cases.len());
            cases.push(BranchCase {
                test,
                confidence,
                order,
            });
        }
    }
    cases
}

/// The probes a record implies, per the classification in
/// [`generate_branch_tests`].
fn branch_probes(site: &BranchSite) -> Vec<Probe> {
    if site.guards == GuardedTarget::SwitchArm {
        // A case arm probes its own case value; a named constant that is
        // not a literal probes null/zero rather than fabricating a value.
        return vec![site
            .immediate
            .as_deref()
            .and_then(parse_probe)
            .unwrap_or(Probe::Zero)];
    }
    match (site.operator.as_deref(), site.immediate.as_deref()) {
        (Some("==" | "!="), Some(imm)) => match parse_probe(imm) {
            // A guard against zero is a null check: probe null/zero.
            None | Some(Probe::Value(0)) => vec![Probe::Zero],
            Some(probe) => vec![probe],
        },
        (Some("<" | "<=" | ">" | ">="), Some(imm)) => match parse_probe(imm) {
            Some(Probe::Value(n)) => [n.checked_sub(1), n.checked_add(1)]
                .into_iter()
                .flatten()
                .map(Probe::Value)
                .collect(),
            Some(Probe::Float(f)) => vec![Probe::Float(f - 1.0), Probe::Float(f + 1.0)],
            // A guard that read no constant claims no boundary.
            None | Some(Probe::Zero) => vec![Probe::Zero],
        },
        // Shape-only readings (no operator) and operator-only readings
        // (the other side is a name, not a constant) claim no boundary:
        // a null/zero probe and nothing else.
        _ => vec![Probe::Zero],
    }
}

/// Parse a record's immediate into a probe value: decimal or `0x` hex in
/// either dialect's spelling, a Ghidra char literal (`'A'`), or a float.
/// A name (`STATE_RUN`) parses to nothing — the record read no constant.
fn parse_probe(text: &str) -> Option<Probe> {
    let text = text.trim();
    if text.len() >= 3 && text.starts_with('\'') && text.ends_with('\'') {
        let inner = &text[1..text.len() - 1];
        let ch = match inner {
            "\\0" => '\0',
            "\\n" => '\n',
            "\\r" => '\r',
            "\\t" => '\t',
            _ if inner.chars().count() == 1 => inner.chars().next()?,
            _ => return None,
        };
        return Some(Probe::Value(i64::from(u32::from(ch))));
    }
    if text.contains('.') {
        return text.parse::<f64>().ok().map(Probe::Float);
    }
    parse_immediate(text).map(Probe::Value)
}

/// The index of the signature parameter a condition name refers to: an
/// exact declared-name match first, then the decompiler's positional
/// spelling — `param_1` names the first parameter. Locals (`local_4`,
/// `DAT_...`) name no parameter.
fn param_index(params: &[ParameterTypeInfo], name: &str) -> Option<usize> {
    if let Some(i) = params
        .iter()
        .position(|p| p.name.as_deref() == Some(name))
    {
        return Some(i);
    }
    let n: usize = name.strip_prefix("param_")?.parse().ok()?;
    (n >= 1 && n <= params.len()).then_some(n - 1)
}

/// Build one branch-targeted case for a parsed signature: a value probe
/// lands on the first parameter the condition names, falling back to the
/// first integer parameter when the condition reads only locals; a
/// null/zero probe zeroes every named parameter — or every parameter when
/// the site names none. All other parameters hold typical values.
fn branch_case_for_signature(
    parsed: &ParsedSignature,
    site: &BranchSite,
    probe: &Probe,
) -> Option<TestCase> {
    let params = &parsed.parameters;
    if params.is_empty() {
        return None;
    }
    let involved: Vec<usize> = site
        .params
        .iter()
        .filter_map(|name| param_index(params, name))
        .collect();
    let target = involved
        .first()
        .copied()
        .or_else(|| params.iter().position(|p| is_integer_type(&p.r#type)))?;
    let mut inputs = serde_json::Map::new();
    for (i, param) in params.iter().enumerate() {
        let value = match probe {
            Probe::Zero if involved.contains(&i) || involved.is_empty() => {
                param_zero_value(param)
            }
            _ if i == target && !matches!(probe, Probe::Zero) => encode_probe(param, probe)?,
            _ => param_typical_value(param),
        };
        inputs.insert(format!("param_{i}"), value);
    }
    Some(TestCase {
        inputs: json!(inputs),
        expected_return: json!(null),
        expected_side_effects: Vec::new(),
    })
}

/// Build one branch-targeted case without a signature, on the generic
/// three-parameter shape [`generate_generic_tests`] uses: the probe lands
/// on the parameter the condition names positionally (`param_1` becomes
/// `param_0`), else on `param_0`; the rest hold zero.
fn branch_case_generic(site: &BranchSite, probe: &Probe) -> Option<TestCase> {
    let named: Vec<usize> = site
        .params
        .iter()
        .filter_map(|name| name.strip_prefix("param_"))
        .filter_map(|n| n.parse::<usize>().ok())
        .filter(|n| (1..=3).contains(n))
        .map(|n| n - 1)
        .collect();
    let target = named.first().copied().unwrap_or(0);
    let probe_value = match probe {
        Probe::Zero => json!(0),
        Probe::Value(n) => json!(n),
        Probe::Float(f) => json!(f),
    };
    let mut inputs = serde_json::Map::new();
    for i in 0..3 {
        inputs.insert(
            format!("param_{i}"),
            if i == target {
                probe_value.clone()
            } else {
                json!(0)
            },
        );
    }
    Some(TestCase {
        inputs: json!(inputs),
        expected_return: json!(null),
        expected_side_effects: Vec::new(),
    })
}

/// Encode a probe as a JSON value the Wine harness can marshal for this
/// parameter type: integers respect the declared width and signedness (a
/// probe outside the representable range drops the case rather than
/// producing an input the harness would reject), floats stay floats, and
/// a pointer probe is an address — zero for the null probe.
fn encode_probe(param: &ParameterTypeInfo, probe: &Probe) -> Option<serde_json::Value> {
    match probe {
        Probe::Zero => Some(param_zero_value(param)),
        Probe::Float(f) => {
            if param.r#type.contains("float") || param.r#type.contains("double") {
                Some(json!(*f))
            } else {
                None
            }
        }
        Probe::Value(n) => {
            if is_pointer_type(&param.r#type) {
                return (n >= &0).then(|| json!(*n as u64));
            }
            if param.r#type.contains("float") || param.r#type.contains("double") {
                return Some(json!(*n as f64));
            }
            if !is_integer_type(&param.r#type) {
                return None;
            }
            probe_fits(param, *n).then(|| json!(*n))
        }
    }
}

/// The declared width of an integer parameter in bits. `ParameterTypeInfo`
/// carries a width only for digit spellings (`int8`); the spelled-out C
/// dialects both front ends emit — `unsigned char`, `short`, `long long` —
/// get their width from the keyword, matching the scalar kinds the Wine
/// harness range-checks on.
fn declared_bit_width(param: &ParameterTypeInfo) -> Option<u32> {
    param.bit_width.or_else(|| {
        let t = param.r#type.trim().to_lowercase();
        if t.contains("char") || t.contains("byte") {
            Some(8)
        } else if t.contains("dword") {
            Some(32)
        } else if t.contains("short") || t.contains("word") {
            Some(16)
        } else if t.contains("long long") || t.contains("i64") {
            Some(64)
        } else if t.contains("long") || t.contains("int") {
            Some(32)
        } else {
            None
        }
    })
}

/// Whether an integer probe sits inside the parameter's declared range.
/// A parameter with no known width accepts any probe — the harness's own
/// range check is the backstop, as it is for today's boundary values.
fn probe_fits(param: &ParameterTypeInfo, n: i64) -> bool {
    match (declared_bit_width(param), param.is_signed) {
        (Some(w), true) if w < 64 => -(1i64 << (w - 1)) <= n && n < 1i64 << (w - 1),
        (Some(w), false) if w < 64 => n >= 0 && n < 1i64 << w,
        (Some(_), false) => n >= 0,
        _ => true,
    }
}

/// Get boundary values for a single parameter type.
fn param_boundary_values(
    param: &ParameterTypeInfo,
    edge_cases: &DisassemblyEdgeCases,
) -> Vec<serde_json::Value> {
    let mut values = Vec::new();

    match param.r#type.as_str() {
        "int" | "i32" | "INT32" | "LONG" | "DWORD" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i32::MIN as i64));
                values.push(json!(i32::MAX as i64));
                values.push(json!(1));
                values.push(json!(-100));
                values.push(json!(100));
            } else {
                values.push(json!(0));
                values.push(json!(u32::MAX));
                values.push(json!(1));
                values.push(json!(100));
                values.push(json!(256));
            }
        }
        "short" | "i16" | "INT16" | "USHORT" | "WORD" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i16::MIN as i64));
                values.push(json!(i16::MAX as i64));
                values.push(json!(1));
            } else {
                values.push(json!(0));
                values.push(json!(u16::MAX));
                values.push(json!(1));
                values.push(json!(100));
            }
        }
        "char" | "i8" | "INT8" | "UCHAR" | "BYTE" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i8::MIN as i64));
                values.push(json!(i8::MAX as i64));
            } else {
                values.push(json!(0));
                values.push(json!(u8::MAX));
                values.push(json!(1));
                values.push(json!(255));
            }
        }
        "long long" | "i64" | "INT64" | "LONGLONG" | "ULONG64" => {
            if param.is_signed {
                values.push(json!(0));
                values.push(json!(-1));
                values.push(json!(i64::MIN));
                values.push(json!(i64::MAX));
            } else {
                values.push(json!(0u64));
                values.push(json!(u64::MAX));
                values.push(json!(1u64));
            }
        }
        "bool" | "BOOL" => {
            values.push(json!(false));
            values.push(json!(true));
        }
        "float" => {
            values.push(json!(0.0f32));
            values.push(json!(-1.0f32));
            values.push(json!(1.0f32));
            values.push(json!(f32::MAX));
            values.push(json!(f32::MIN));
        }
        "double" => {
            values.push(json!(0.0f64));
            values.push(json!(-1.0f64));
            values.push(json!(1.0f64));
            values.push(json!(f64::MAX));
            values.push(json!(f64::MIN));
        }
        _ if param.is_pointer => {
            // Null and valid pointer (represented as address)
            values.push(json!(0));
            values.push(json!(0x1000u64));
        }
        _ if param.r#type.contains("char") && param.is_pointer => {
            // String/char pointer
            values.push(json!(""));
            values.push(json!("a"));
            values.push(json!("test"));
            values.push(json!(null));
        }
        _ => {
            // Default: zero/null values
            values.push(json!(0));
            values.push(json!(0u32));
            values.push(json!(0u64));
        }
    }

    // Add edge cases from disassembly that apply to this parameter
    for boundary in edge_cases.get_boundary_values() {
        if is_integer_type(&param.r#type) {
            values.push(json!(if param.is_signed {
                boundary
            } else {
                (boundary as u64).min(u32::MAX as u64) as i64
            }));
        }
    }

    // Deduplicate
    let mut seen = HashSet::new();
    values.retain(|v| seen.insert(v.to_string()));

    values
}

/// Get the default value for a parameter type.
fn param_default_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_integer_type(&param.r#type) {
        if param.is_signed {
            json!(0i64)
        } else {
            json!(0u32)
        }
    } else if is_pointer_type(&param.r#type) {
        json!(null)
    } else if param.r#type.contains("float") || param.r#type.contains("double") {
        json!(0.0f64)
    } else if param.r#type.contains("bool") || param.r#type.contains("BOOL") {
        json!(false)
    } else {
        json!(0)
    }
}

/// Get a zero value for a parameter type.
fn param_zero_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_pointer_type(&param.r#type) {
        json!(0u64)
    } else if is_integer_type(&param.r#type) {
        json!(0i64)
    } else {
        json!(0)
    }
}

/// Get a typical/normal value for a parameter type.
fn param_typical_value(param: &ParameterTypeInfo) -> serde_json::Value {
    if is_integer_type(&param.r#type) {
        if param.is_signed {
            json!(42i64)
        } else {
            json!(42u32)
        }
    } else if is_pointer_type(&param.r#type) {
        json!(0u64)
    } else if param.r#type.contains("float") || param.r#type.contains("double") {
        json!(1.0f64)
    } else if param.r#type.contains("bool") || param.r#type.contains("BOOL") {
        json!(true)
    } else {
        json!(0)
    }
}

/// Get the maximum value for a parameter type.
fn param_max_value(param: &ParameterTypeInfo) -> serde_json::Value {
    match param.r#type.as_str() {
        "int" | "i32" | "INT32" | "LONG" => json!(i32::MAX as i64),
        "unsigned int" | "UINT" | "DWORD" => json!(u32::MAX),
        "short" | "i16" | "INT16" => json!(i16::MAX as i64),
        "unsigned short" | "USHORT" | "WORD" => json!(u16::MAX),
        "char" | "i8" | "INT8" => json!(i8::MAX as i64),
        "unsigned char" | "UCHAR" | "BYTE" => json!(u8::MAX),
        "long long" | "i64" | "INT64" | "LONGLONG" => json!(i64::MAX),
        "unsigned long long" | "ULONG64" | "ULONGLONG" => json!(u64::MAX),
        "float" => json!(f32::MAX as f64),
        "double" => json!(f64::MAX),
        "bool" | "BOOL" => json!(true),
        _ if param.r#type.ends_with('*') => json!(0u64),
        _ => json!(0),
    }
}

/// Check if a parameter type is an integer type.
fn is_integer_type(type_str: &str) -> bool {
    let t = type_str.trim().to_lowercase();
    t.contains("int")
        || t.contains("long")
        || t.contains("short")
        || t.contains("char")
        || t.contains("byte")
        || t.contains("uint")
        || t.contains("ulong")
        || t.contains("ushort")
        || t.contains("uchar")
        || t == "bool"
        || t == "BOOL"
        || t == "integer"
}

/// Check if a parameter type is a pointer type.
fn is_pointer_type(type_str: &str) -> bool {
    type_str.trim().ends_with('*')
}

/// Check if the parameter list has any integer parameters.
fn has_integer_params(params: &[ParameterTypeInfo]) -> bool {
    params.iter().any(|p| is_integer_type(&p.r#type))
}

/// Deduplicate test cases by their input values.
fn deduplicate_tests(tests: Vec<TestCase>) -> Vec<TestCase> {
    let mut seen = HashSet::new();
    tests
        .into_iter()
        .filter(|t| {
            let key = t.inputs.to_string();
            seen.insert(key)
        })
        .collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ghidra_mcp_style_lowercase_text_still_reads() {
        // The lowercase objdump-style spelling the retired bridge served —
        // the Kuna additions must not change what this yields.
        let cases = DisassemblyEdgeCases::from_disassembly(
            "cmp eax, 0\nje zero_handler\ncmp ecx, 256\nja out_of_bounds\ncmp edx, -1\ntest eax, eax",
        );
        assert_eq!(cases.boundary_checks, vec![256]);
        assert_eq!(cases.negative_checks, vec![-1]);
        assert!(cases.zero_checks.contains("cmp_zero"));
    }

    #[test]
    fn kuna_disassembly_text_yields_boundary_values() {
        // Kuna's disassembly listing is SLEIGH-style: uppercase mnemonics
        // and `0x`-prefixed hex immediates, one space between mnemonic and
        // operands.
        let cases = DisassemblyEdgeCases::from_disassembly(
            "0x1800010a0  83 f8 64  CMP EAX,0x64\n\
             0x1800010a3  85 c0     TEST EAX,EAX\n\
             0x1800010a5  74 0c     JE 0x1800010b3\n\
             0x1800010aa  3c 0a     CMP AL,0x0A",
        );
        assert_eq!(cases.boundary_checks, vec![100, 10]);
        assert_eq!(cases.get_boundary_values(), vec![10, 100]);
    }

    #[test]
    fn a_kuna_hex_zero_check_reads_as_zero() {
        let cases = DisassemblyEdgeCases::from_disassembly("CMP EAX,0x0\nTEST ECX,0x0");
        assert!(cases.zero_checks.contains("cmp_zero"));
        assert!(cases.zero_checks.contains("test_zero"));
    }

    // ---- branch-targeted cases -------------------------------------

    /// One branch-site record for the inventory a test hands the seam.
    fn sample_branch_site(
        condition: &str,
        params: &[&str],
        operator: Option<&str>,
        immediate: Option<&str>,
        guards: GuardedTarget,
        confidence: u8,
    ) -> BranchSite {
        BranchSite {
            function: "FUN_18003ab00".into(),
            condition: condition.into(),
            params: params.iter().map(|p| (*p).to_string()).collect(),
            operator: operator.map(str::to_string),
            immediate: immediate.map(str::to_string),
            guards,
            suggestion: String::new(),
            confidence: calxgloss_types::Confidence::new(confidence),
            evidence: String::new(),
        }
    }

    /// The input sets a suite carries, as dedup keys.
    fn input_keys(tests: &[TestCase]) -> HashSet<String> {
        tests.iter().map(|t| t.inputs.to_string()).collect()
    }

    /// The value fed to one input key across a suite.
    fn probed_values(tests: &[TestCase], key: &str) -> Vec<serde_json::Value> {
        tests
            .iter()
            .filter_map(|t| t.inputs.get(key).cloned())
            .collect()
    }

    #[test]
    fn an_empty_inventory_leaves_the_output_byte_identical() {
        // The seam grew an inventory parameter; with an empty inventory
        // the same signature and disassembly must produce byte-identical
        // suites to the ones recorded before the seam grew — over the
        // signature+disassembly, signature-only, and disassembly-only
        // paths.
        const GOLDEN_SIG_DIS: &str =
            include_str!("../tests/golden/testgen_empty_inventory_sig_dis.json");
        const GOLDEN_SIG_ONLY: &str =
            include_str!("../tests/golden/testgen_empty_inventory_sig_only.json");
        const GOLDEN_DIS_ONLY: &str =
            include_str!("../tests/golden/testgen_empty_inventory_dis_only.json");
        let sig = "HRESULT __stdcall FooBar(BSTR inText, double scale, LONG count, VARIANT_BOOL flag, POINT pt, RECT rc, SAFEARRAY* arr)";
        let dis = "FooBar:\n0000: 8B 44 81 0C    mov    eax,[ecx+eax*4+0xc]\n0001: 3B D3            cmp    edx,ebx\n0002: 75 04            jne    0x8\n0003: 85 C0            test   eax,eax\n0004: 74 02            je     0x10\n";
        assert_eq!(
            serde_json::to_string(&generate_test_inputs(sig, dis, &[]).unwrap()).unwrap(),
            GOLDEN_SIG_DIS.trim_end()
        );
        assert_eq!(
            serde_json::to_string(&generate_test_inputs(sig, "", &[]).unwrap()).unwrap(),
            GOLDEN_SIG_ONLY.trim_end()
        );
        assert_eq!(
            serde_json::to_string(&generate_test_inputs("", dis, &[]).unwrap()).unwrap(),
            GOLDEN_DIS_ONLY.trim_end()
        );
    }

    #[test]
    fn an_equality_guard_yields_its_equality_value() {
        let sig = "int __stdcall Check(int x)";
        let inventory = [sample_branch_site(
            "param_1 == 256",
            &["param_1"],
            Some("=="),
            Some("256"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert!(probed_values(&tests, "param_0").contains(&json!(256)));
    }

    #[test]
    fn a_relational_guard_yields_the_immediate_plus_and_minus_one() {
        // The pair straddles the boundary, so an off-by-one mistranslation
        // of the loop exit diverges on one of the two probes.
        let sig = "int __stdcall Sum(int x)";
        let inventory = [sample_branch_site(
            "param_1 < 10",
            &["param_1"],
            Some("<"),
            Some("10"),
            GuardedTarget::LoopExit,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        let probed = probed_values(&tests, "param_0");
        assert!(probed.contains(&json!(9)), "the keep-looping side is probed");
        assert!(probed.contains(&json!(11)), "the loop-exit side is probed");
    }

    #[test]
    fn a_null_check_guard_yields_a_null_zero_probe_and_nothing_else() {
        // `param_1 == 0` is a null check: the guard against zero probes
        // null/zero on the parameter it names and claims no other
        // boundary — the single case it adds zeroes that parameter and
        // holds the rest typical.
        let sig = "int __stdcall Idx(int i, int n)";
        let inventory = [sample_branch_site(
            "param_1 == 0",
            &["param_1"],
            Some("=="),
            Some("0"),
            GuardedTarget::ErrorPath,
            80,
        )];
        let without = generate_test_inputs(sig, "", &[]).unwrap();
        let with = generate_test_inputs(sig, "", &inventory).unwrap();
        let held = input_keys(&without);
        let new: Vec<&serde_json::Value> = with
            .iter()
            .map(|t| &t.inputs)
            .filter(|inputs| !held.contains(&inputs.to_string()))
            .collect();
        assert_eq!(
            new,
            vec![&json!({"param_0": 0, "param_1": 42})],
            "the null/zero probe is the only case a guard against zero adds"
        );
    }

    #[test]
    fn a_shape_only_record_yields_only_a_null_zero_probe() {
        // A compound condition reads shape-only: it names its parameters
        // but claims no boundary, so the only case it adds zeroes them
        // and holds the rest typical.
        let sig = "int __stdcall Gate(int a, int b, int c)";
        let inventory = [sample_branch_site(
            "param_1 == 0 && param_2 == 1",
            &["param_1", "param_2"],
            None,
            None,
            GuardedTarget::EarlyReturn,
            50,
        )];
        let without = generate_test_inputs(sig, "", &[]).unwrap();
        let with = generate_test_inputs(sig, "", &inventory).unwrap();
        let held = input_keys(&without);
        let new: Vec<&serde_json::Value> = with
            .iter()
            .map(|t| &t.inputs)
            .filter(|inputs| !held.contains(&inputs.to_string()))
            .collect();
        assert_eq!(
            new,
            vec![&json!({"param_0": 0, "param_1": 0, "param_2": 42})],
            "the null/zero probe is the only case a shape-only reading adds"
        );
    }

    #[test]
    fn a_switch_yields_one_case_value_per_arm() {
        let sig = "int __stdcall Dispatch(int op)";
        let inventory = [
            sample_branch_site("case 1:", &[], None, Some("1"), GuardedTarget::SwitchArm, 80),
            sample_branch_site("case 2:", &[], None, Some("2"), GuardedTarget::SwitchArm, 80),
        ];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        let probed = probed_values(&tests, "param_0");
        assert!(probed.contains(&json!(1)));
        assert!(probed.contains(&json!(2)));
    }

    #[test]
    fn a_named_case_constant_probes_null_zero_instead_of_a_fabricated_value() {
        // `case STATE_RUN:` names no literal; the record fabricates no
        // value, so its probe is the null/zero one — which for this
        // signature already sits in the suite as a boundary case.
        let sig = "int __stdcall State(int s)";
        let inventory = [sample_branch_site(
            "case STATE_RUN:",
            &["STATE_RUN"],
            None,
            Some("STATE_RUN"),
            GuardedTarget::SwitchArm,
            70,
        )];
        let without = generate_test_inputs(sig, "", &[]).unwrap();
        let with = generate_test_inputs(sig, "", &inventory).unwrap();
        assert_eq!(with.len(), without.len());
        assert!(probed_values(&with, "param_0").contains(&json!(0)));
    }

    #[test]
    fn parameters_the_condition_does_not_involve_hold_typical_values() {
        let sig = "int __stdcall Clamp(int x, int lo)";
        let inventory = [sample_branch_site(
            "param_1 == 7",
            &["param_1"],
            Some("=="),
            Some("7"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert!(tests
            .iter()
            .any(|t| t.inputs == json!({"param_0": 7, "param_1": 42})));
    }

    #[test]
    fn a_condition_naming_a_declared_parameter_lands_on_it() {
        let sig = "int __stdcall Clamp(int count, int max)";
        let inventory = [sample_branch_site(
            "max == 0",
            &["max"],
            Some("=="),
            Some("0"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert!(tests
            .iter()
            .any(|t| t.inputs == json!({"param_0": 42, "param_1": 0})));
    }

    #[test]
    fn branch_cases_deduplicate_against_existing_boundary_cases() {
        // 100 is already a boundary value for a signed int parameter, so
        // the equality probe adds no case.
        let sig = "int __stdcall Neg(int x)";
        let inventory = [sample_branch_site(
            "param_1 == 100",
            &["param_1"],
            Some("=="),
            Some("100"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let without = generate_test_inputs(sig, "", &[]).unwrap();
        let with = generate_test_inputs(sig, "", &inventory).unwrap();
        assert_eq!(
            serde_json::to_string(&with).unwrap(),
            serde_json::to_string(&without).unwrap(),
            "a probe duplicating a boundary case adds nothing"
        );
    }

    #[test]
    fn the_cap_drops_the_lowest_confidence_branch_cases_first() {
        // Enough exact readings to bite the cap, plus one shape-only
        // reading whose probe is a distinct input set: the 50-confidence
        // probe goes first, then the later sites among the 80s.
        let sig = "int __stdcall Wide(int x, int y)";
        let without = generate_test_inputs(sig, "", &[]).unwrap();
        let mut inventory: Vec<BranchSite> = (2..32)
            .map(|i| {
                sample_branch_site(
                    &format!("param_1 == {i}"),
                    &["param_1"],
                    Some("=="),
                    Some(&i.to_string()),
                    GuardedTarget::EarlyReturn,
                    80,
                )
            })
            .collect();
        inventory.push(sample_branch_site(
            "param_1 == 0 && local_4",
            &["param_1"],
            None,
            None,
            GuardedTarget::EarlyReturn,
            50,
        ));
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert_eq!(tests.len(), MAX_TEST_CASES_PER_FUNCTION);
        assert!(
            without.len() < MAX_TEST_CASES_PER_FUNCTION,
            "the cap bites on the branch cases, not the boundary suite"
        );
        let probed = probed_values(&tests, "param_0");
        // The shape-only probe ({0, 42}) is gone...
        assert!(!tests
            .iter()
            .any(|t| t.inputs == json!({"param_0": 0, "param_1": 42})));
        // ...and among the exact readings the later sites dropped first:
        // every probe up to the boundary survives, every probe past it
        // does not.
        let room = MAX_TEST_CASES_PER_FUNCTION - without.len();
        let dropped = 31 - room; // 30 exact probes plus the shape-only one
        assert!(dropped >= 1, "the inventory is meant to bite the cap");
        let highest_kept = 32 - dropped;
        assert!(probed.contains(&json!(highest_kept)));
        assert!(!probed.contains(&json!(highest_kept + 1)));
    }

    #[test]
    fn a_kuna_hex_immediate_and_a_ghidra_char_literal_probe_their_values() {
        let sig = "int __stdcall Key(int k)";
        let inventory = [
            sample_branch_site(
                "param_1 == 0x64",
                &["param_1"],
                Some("=="),
                Some("0x64"),
                GuardedTarget::EarlyReturn,
                80,
            ),
            sample_branch_site(
                "param_1 == 'A'",
                &["param_1"],
                Some("=="),
                Some("'A'"),
                GuardedTarget::ErrorPath,
                80,
            ),
        ];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        let probed = probed_values(&tests, "param_0");
        assert!(probed.contains(&json!(100)), "Kuna's hex immediate reads");
        assert!(probed.contains(&json!(65)), "Ghidra's char literal reads");
    }

    #[test]
    fn a_probe_outside_the_parameter_range_is_skipped() {
        // 300 does not fit an unsigned char parameter: the case would be
        // unencodable for the Wine harness, so it is dropped.
        let sig = "int __stdcall B(unsigned char b)";
        let inventory = [sample_branch_site(
            "param_1 == 300",
            &["param_1"],
            Some("=="),
            Some("300"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert!(!probed_values(&tests, "param_0").contains(&json!(300)));
    }

    #[test]
    fn an_operator_only_reading_probes_null_zero_not_a_fabricated_boundary() {
        // `param_1 == STATE_IDLE` read the operator but the other side is
        // a name: no boundary is claimed, so the probe zeroes the named
        // parameter and holds the rest typical.
        let sig = "int __stdcall S(int x, int y)";
        let inventory = [sample_branch_site(
            "param_1 == STATE_IDLE",
            &["param_1"],
            Some("=="),
            None,
            GuardedTarget::EarlyReturn,
            70,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        assert!(tests
            .iter()
            .any(|t| t.inputs == json!({"param_0": 0, "param_1": 42})));
    }

    #[test]
    fn a_condition_naming_only_locals_probes_the_first_integer_parameter() {
        let sig = "int __stdcall Loop(int n)";
        let inventory = [sample_branch_site(
            "local_9 < 3",
            &["local_9"],
            Some("<"),
            Some("3"),
            GuardedTarget::LoopExit,
            80,
        )];
        let tests = generate_test_inputs(sig, "", &inventory).unwrap();
        let probed = probed_values(&tests, "param_0");
        assert!(probed.contains(&json!(2)));
        assert!(probed.contains(&json!(4)));
    }

    #[test]
    fn a_branch_case_without_a_signature_uses_the_generic_shape() {
        let inventory = [sample_branch_site(
            "param_1 == 7",
            &["param_1"],
            Some("=="),
            Some("7"),
            GuardedTarget::EarlyReturn,
            80,
        )];
        let tests = generate_test_inputs("", "", &inventory).unwrap();
        assert!(tests
            .iter()
            .any(|t| t.inputs == json!({"param_0": 7, "param_1": 0, "param_2": 0})));
    }
}
