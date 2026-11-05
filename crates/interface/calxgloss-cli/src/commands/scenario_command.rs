//! The `scenario` command family — authoring scenario contracts (P24.1,
//! issue #402).
//!
//! Declaring is authoring, not running: the command validates a declared
//! **scenario contract** and files it in the record tree as one owned
//! document per target binary under `re/scenarios/{binary}.json` — the
//! interface-owned document that later scenario slices capture against
//! and replay (pipeline and testgen only read it).
//!
//! A malformed declaration is an input error, refused at declare time
//! naming the offending field: an unresolvable working dir, an
//! observation path escaping the run dir, or an absurd timing value
//! never files, so no bogus contract waits downstream. Re-declaring a
//! scenario replaces its contract outright; several scenarios per target
//! binary coexist in the one document. A sensitive scripted input
//! (`--secret-at`) never persists its text — only the byte count files,
//! and the e2e pin proves the secret appears nowhere in the filed bytes.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use calxgloss_testgen::{WineRunner, capture_scenario};
use calxgloss_types::{
    BinaryIdentity, ExitDisposition, InteractionKind, LiteralReplacement, NormalizationRules,
    PersistError, ScenarioCapture, ScenarioContract, ScenarioContracts, ScenarioSignal,
    ScriptedInput, ScriptedInteraction, load_json, save_json, scenario_capture_path,
    scenario_contracts_path,
};

/// The gathered flags of one `scenario declare`, mirroring the variant's
/// fields so the match arm stays a plain move.
pub struct ScenarioDeclareOptions {
    /// Scenario name, unique per target binary.
    pub scenario: String,
    /// Working dir the scenario run starts in.
    pub working_dir: String,
    /// `KEY=VALUE` environment entries.
    pub env: Vec<String>,
    /// The scenario run's argv entries.
    pub argv: Vec<String>,
    /// `MS:TEXT` typed-input interactions.
    pub inputs: Vec<String>,
    /// `MS:TEXT` sensitive typed-input interactions (byte-count filed).
    pub secrets: Vec<String>,
    /// `MS:COLSxROWS` console resizes.
    pub resizes: Vec<String>,
    /// `MS:interrupt|break` signals.
    pub signals: Vec<String>,
    /// Observation paths relative to the run dir.
    pub observe: Vec<String>,
    /// Console columns at start.
    pub cols: u16,
    /// Console rows at start.
    pub rows: u16,
    /// Idle window, in ms.
    pub idle_timeout_ms: u64,
    /// Max run duration, in ms.
    pub max_run_ms: u64,
    /// SIGTERM→SIGKILL grace, in ms.
    pub finalization_grace_ms: u64,
    /// Terminal output cap, in bytes.
    pub max_output_bytes: u64,
    /// Version of the normalization rules in force.
    pub normalize_version: String,
    /// `FROM=TO` literal replacements.
    pub normalize_literals: Vec<String>,
    /// Port patterns masked out of comparison.
    pub normalize_ports: Vec<String>,
}

/// Parse an `MS:REST` interaction value, naming the flag on a malformed
/// one — a wrong flag value is refused before anything domain-level runs.
fn at_offset<'a>(flag: &str, value: &'a str) -> Result<(u64, &'a str)> {
    let (ms, rest) = value
        .split_once(':')
        .ok_or_else(|| anyhow!("`{flag}` expects MS:VALUE, got `{value}`"))?;
    let ms = ms.parse::<u64>().map_err(|_| {
        anyhow!("`{flag}` needs a millisecond offset before the `:`, got `{value}`")
    })?;
    Ok((ms, rest))
}

/// Fold the gathered flags into a contract, refusing malformed flag
/// values by name. Sensitive inputs take their storage form right here:
/// the text is measured, never carried.
fn build_contract(options: &ScenarioDeclareOptions) -> Result<ScenarioContract> {
    let mut env = BTreeMap::new();
    for entry in &options.env {
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("`--env` expects KEY=VALUE, got `{entry}`"))?;
        env.insert(key.to_string(), value.to_string());
    }
    let mut interactions = Vec::new();
    for value in &options.inputs {
        let (at_ms, text) = at_offset("--input-at", value)?;
        interactions.push(ScriptedInteraction {
            at_ms,
            kind: InteractionKind::Input {
                text: ScriptedInput::Text(text.to_string()),
            },
        });
    }
    for value in &options.secrets {
        let (at_ms, text) = at_offset("--secret-at", value)?;
        interactions.push(ScriptedInteraction {
            at_ms,
            kind: InteractionKind::Input {
                text: ScriptedInput::ByteCount {
                    bytes: text.len() as u64,
                },
            },
        });
    }
    for value in &options.resizes {
        let (at_ms, geometry) = at_offset("--resize-at", value)?;
        let (cols, rows) = geometry
            .split_once('x')
            .ok_or_else(|| anyhow!("`--resize-at` expects MS:COLSxROWS, got `{value}`"))?;
        let (Ok(cols), Ok(rows)) = (cols.parse::<u16>(), rows.parse::<u16>()) else {
            bail!("`--resize-at` needs a COLSxROWS geometry after the `:`, got `{value}`");
        };
        interactions.push(ScriptedInteraction {
            at_ms,
            kind: InteractionKind::Resize { cols, rows },
        });
    }
    for value in &options.signals {
        let (at_ms, name) = at_offset("--signal-at", value)?;
        let signal = match name {
            "interrupt" => ScenarioSignal::Interrupt,
            "break" => ScenarioSignal::Break,
            other => bail!("`--signal-at` accepts `interrupt` or `break`, got `{other}`"),
        };
        interactions.push(ScriptedInteraction {
            at_ms,
            kind: InteractionKind::Signal { signal },
        });
    }
    interactions.sort_by_key(|interaction| interaction.at_ms);
    let mut literal_replacements = Vec::new();
    for entry in &options.normalize_literals {
        let (from, to) = entry
            .split_once('=')
            .ok_or_else(|| anyhow!("`--normalize-literal` expects FROM=TO, got `{entry}`"))?;
        literal_replacements.push(LiteralReplacement {
            from: from.to_string(),
            to: to.to_string(),
        });
    }
    Ok(ScenarioContract {
        name: options.scenario.clone(),
        working_dir: options.working_dir.clone(),
        env,
        argv: options.argv.clone(),
        interactions,
        cols: options.cols,
        rows: options.rows,
        observation_paths: options.observe.clone(),
        idle_timeout_ms: options.idle_timeout_ms,
        max_run_ms: options.max_run_ms,
        finalization_grace_ms: options.finalization_grace_ms,
        max_output_bytes: options.max_output_bytes,
        normalization: NormalizationRules {
            version: options.normalize_version.clone(),
            literal_replacements,
            port_patterns: options.normalize_ports.clone(),
        },
    })
}

/// The contract document's name is the binary identity verbatim — so a
/// declared identity carrying path shape (`../evil`, `sub/dir/x.exe`)
/// would file outside the owner directory, silently breaking the
/// "keyed by binary identity" rule. The declare path refuses it naming
/// the flag; the identity itself stays unnormalized (identity doctrine).
fn reject_path_shaped_identity(binary: &str) -> Result<()> {
    let mut components = Path::new(binary).components();
    let bare = matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    );
    if !bare || binary.is_empty() {
        bail!(
            "`--binary` must be a bare binary identity, e.g. `eqgame.exe` — `{binary}` carries path shape and would file outside the owner directory"
        );
    }
    Ok(())
}

/// Declare one scenario contract for `binary` and file it in the
/// record tree.
///
/// `workspace` keys the document (`re/scenarios/{binary}.json`);
/// `validation_root` resolves a relative working dir — the target
/// directory when one is configured, else the workspace. A refusal names
/// its offending field and files nothing; a filed document always
/// carries its binary envelope, and a document speaking for a different
/// binary is refused rather than mixed.
pub fn handle_scenario_declare(
    binary: &str,
    options: &ScenarioDeclareOptions,
    workspace: &Path,
    validation_root: &Path,
) -> Result<()> {
    reject_path_shaped_identity(binary)?;
    let binary = BinaryIdentity::new(binary);
    let contract = build_contract(options)?;
    let path = scenario_contracts_path(workspace, &binary);
    let mut documents = match load_json::<ScenarioContracts>(&path) {
        Ok(documents) => {
            if documents.binary != binary {
                bail!(
                    "the contract document filed at {} speaks for {}, not {binary} — refusing to author across binaries",
                    path.display(),
                    documents.binary
                );
            }
            documents
        }
        Err(PersistError::NotFound { .. }) => ScenarioContracts {
            binary: binary.clone(),
            filed_at: 0,
            scenarios: BTreeMap::new(),
        },
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "reading the contract document at {}",
                path.display()
            )));
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock stands after 1970")
        .as_secs();
    documents
        .declare(contract.clone(), validation_root, now)
        .map_err(|error| anyhow!(error))?;
    save_json(&path, &documents)
        .with_context(|| format!("filing the contract document at {}", path.display()))?;
    println!(
        "scenario '{}' declared for {binary}: {} contract(s) filed at {}",
        contract.name,
        documents.scenarios.len(),
        path.display()
    );
    println!(
        "  working dir `{}`, idle {} ms / max run {} ms, grace {} ms, output cap {} bytes, {} interaction(s), {} observation path(s)",
        contract.working_dir,
        contract.idle_timeout_ms,
        contract.max_run_ms,
        contract.finalization_grace_ms,
        contract.max_output_bytes,
        contract.interactions.len(),
        contract.observation_paths.len(),
    );
    Ok(())
}

/// The `scenario capture` arm (P24.3, issue #404): run the declared
/// contract against the original target binary and file the scenario
/// capture. The interface owns the load, the filing, and the pairing
/// statement; the run itself belongs to testgen's scenario-run seam.
///
/// The pairing rule stands here at the filing point: a re-capture
/// replaces the previous document outright — exactly one current capture
/// per scenario name — but when the standing capture ran different
/// program bytes, the mismatch is stated out loud before the
/// replacement, never silent.
pub fn handle_scenario_capture(
    binary: &str,
    scenario: &str,
    workspace: &Path,
    validation_root: &Path,
) -> Result<()> {
    reject_path_shaped_identity(binary)?;
    let binary = BinaryIdentity::new(binary);

    // A capture runs a declaration, it never invents one: the filed
    // contract document must stand and speak for this binary.
    let contracts_path = scenario_contracts_path(workspace, &binary);
    let documents = match load_json::<ScenarioContracts>(&contracts_path) {
        Ok(documents) => documents,
        Err(PersistError::NotFound { .. }) => {
            bail!(
                "no contract document for {binary} at {} — declare the scenario before capturing it",
                contracts_path.display()
            );
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context(format!(
                "reading the contract document at {}",
                contracts_path.display()
            )));
        }
    };
    if documents.binary != binary {
        bail!(
            "the contract document filed at {} speaks for {}, not {binary} — refusing to capture across binaries",
            contracts_path.display(),
            documents.binary
        );
    }
    let contract = documents.scenarios.get(scenario).cloned().ok_or_else(|| {
        let declared: Vec<&str> = documents.scenarios.keys().map(String::as_str).collect();
        anyhow!("scenario '{scenario}' is not declared for {binary} — declared here: {declared:?}")
    })?;
    contract.validate(validation_root)?;

    // The original target binary: the identity names a file under the
    // validation root; the run stands in the contract's working dir.
    let program = validation_root.join(binary.as_str());
    if !program.is_file() {
        bail!(
            "the original target binary is not at {} — the binary identity must name a file in the target dir",
            program.display()
        );
    }
    let working = Path::new(&contract.working_dir);
    let run_dir = if working.is_absolute() {
        working.to_path_buf()
    } else {
        validation_root.join(working)
    };

    let wine = WineRunner::new(workspace);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock stands after 1970")
        .as_secs();
    let capture = capture_scenario(&program, &run_dir, &contract, &wine, now)?;

    let path = scenario_capture_path(workspace, &binary, scenario);
    if let Ok(standing) = load_json::<ScenarioCapture>(&path) {
        state_pairing_mismatch(&standing, &capture, &path);
    }
    save_json(&path, &capture)
        .with_context(|| format!("filing the scenario capture at {}", path.display()))?;

    println!(
        "scenario '{scenario}' captured against {binary}: {}",
        disposition_summary(&capture)
    );
    println!(
        "  filed at {} — {} output byte(s) recorded{}, {} interaction(s) acknowledged, {} observation path(s) classified",
        path.display(),
        capture
            .terminal
            .as_ref()
            .map(|t| t.chunks.iter().map(String::len).sum::<usize>())
            .unwrap_or(0),
        match capture
            .terminal
            .as_ref()
            .and_then(|t| t.output_capped.then_some(()))
        {
            Some(()) => format!(
                " (capped at {} bytes — more was produced)",
                contract.max_output_bytes
            ),
            None => String::new(),
        },
        capture
            .interaction
            .as_ref()
            .map(|i| i.acknowledged_at_ms.len())
            .unwrap_or(0),
        capture
            .filesystem
            .as_ref()
            .map(|f| f.entries.len())
            .unwrap_or(0),
    );
    if let Some(pairing) = &capture.pairing {
        println!(
            "  pairing: program sha256 {}, {}",
            pairing.program_sha256, pairing.wine_version
        );
    }
    Ok(())
}

/// The pairing rule stated out loud: identical pairing stamps pair for
/// comparison — the program's sha256 and the Wine that ran it — and a
/// mismatch on either names both sides before the replacement files,
/// never silent. A reader of the transcript never mistakes a
/// re-capture of changed bytes for a clean re-run.
fn state_pairing_mismatch(standing: &ScenarioCapture, fresh: &ScenarioCapture, path: &Path) {
    let (Some(old), Some(new)) = (&standing.pairing, &fresh.pairing) else {
        return;
    };
    if old == new {
        return;
    }
    let mut parts = Vec::new();
    if old.program_sha256 != new.program_sha256 {
        parts.push(format!(
            "program sha256 {} vs {}",
            old.program_sha256, new.program_sha256
        ));
    }
    if old.wine_version != new.wine_version {
        parts.push(format!("wine {} vs {}", old.wine_version, new.wine_version));
    }
    println!(
        "PAIRING MISMATCH: the capture standing at {} paired differently — {}; \
         captures pair for comparison only against identical pairing stamps, and the replacement files as the current capture",
        path.display(),
        parts.join("; ")
    );
}

fn disposition_summary(capture: &ScenarioCapture) -> String {
    let Some(exit) = capture.exit.as_ref() else {
        return "how it ended is unassessed".to_string();
    };
    match exit.disposition {
        ExitDisposition::Exited => match exit.exit_code {
            Some(code) => format!("exited with code {code}"),
            None => "exited (no code reported)".to_string(),
        },
        ExitDisposition::Timeout => "closed by the max-run window".to_string(),
        ExitDisposition::IdleTimeout => "closed by the idle window".to_string(),
        ExitDisposition::Cancelled => "cancelled".to_string(),
        ExitDisposition::Failed => "failed".to_string(),
    }
}
