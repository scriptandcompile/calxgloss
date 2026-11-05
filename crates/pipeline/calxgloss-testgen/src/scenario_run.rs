//! The scenario-run seam (P24.3–P24.4, issues #404, #405): run one declared
//! scenario contract against the original target program under the standing
//! Wine toolchain rules and produce the observed **scenario capture** — exit
//! disposition, raw terminal chunks under the cap with its truncation
//! mark, the before/after classification of the declared observation
//! paths, the interaction acknowledgements, the process samples, and
//! the pairing stamps (the program's sha256 and the Wine that ran it).
//!
//! The run binds an ownership token at launch; both declared windows (idle,
//! max run) close a runaway run through the token-gated SIGTERM→grace→
//! SIGKILL finalization, and every close files its outcome by name —
//! including the token's refusal to touch a pid that answers to a stranger.
//! The process dimension is sampled from the host at the run's own birth
//! anchor, so a program that spawns children shows them in the record. A
//! missing Wine fails the capture by name through the standing preflight
//! line — before any process exists to hang.
//!
//! Standing rule for the future *instrumented* scenario run, recorded
//! here and deliberately unimplemented in this seam: the guest process is
//! spawned **paused**, the target image is **load**ed into it, then it is
//! **resume**d — spawn-paused→load→resume, never a running process probed
//! from outside.
//!
//! This seam owns the *run*; the interface owns loading the contract,
//! filing the document, and the pairing-mismatch statement (compare the
//! CLI's scenario command). An absent capture block reads *unassessed* —
//! the honesty rule — but a run that reached the dimension always names
//! what it saw, and a capped capture never claims more than it saw.

mod files;
#[cfg(unix)]
mod pty;
#[cfg(target_os = "linux")]
mod sampler;

use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use calxgloss_types::{
    CapturePairing, ExitDisposition, ExitObservation, FilesystemObservation, FinalizationOutcome,
    InteractionKind, InteractionObservation, ProcessObservation, ProcessSample, ScenarioCapture,
    ScenarioContract, ScenarioSignal, ScriptedInput, ScriptedInteraction, TerminalGeometry,
    TerminalObservation,
};

use crate::wine::WineRunner;
use crate::wine::owned::{OwnedProcess, Stopped};
#[cfg(unix)]
use pty::INPUT_LINE_END;

/// Run one scenario contract against `program` and return the capture its
/// run was observed to make. `run_dir` is the contract's resolved working
/// dir — the program runs with it as cwd, and the declared observation
/// paths are relative to it. `now` is the filing clock's reading, stamped
/// into the capture as-is; the caller files the document.
pub fn capture_scenario(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
    now: u64,
) -> Result<ScenarioCapture> {
    capture_scenario_with_secrets(program, run_dir, contract, wine, &[], now)
}

/// One capture-time secret: the typed form of one byte-count placeholder
/// the contract filed. It exists only while the run lives — it is never
/// filed, never returned in the capture, and reaching the terminal at all
/// requires it to match its placeholder exactly (see
/// [`validate_typed_secrets`]).
#[derive(Debug, Clone)]
pub struct TypedSecret {
    /// The `at_ms` offset of the placeholder this secret stands for.
    pub at_ms: u64,
    /// The secret text, typed at that offset and nothing else.
    pub text: String,
}

/// Refuse typed secrets the contract did not declare, before anything
/// runs: every one must stand at an offset whose interaction is a
/// byte-count placeholder, and its length must equal the count the
/// placeholder filed. A typed secret is one line — text carrying a
/// control character would ride the terminal as several inputs and
/// steer the console's own line editing, so it is refused even when
/// its count matches — and one placeholder takes exactly one typed
/// form. A capture never types what its contract didn't say — and the
/// refusal arrives before even the Wine preflight, because a secret
/// nobody declared is refused in any toolchain state.
fn validate_typed_secrets(
    contract: &ScenarioContract,
    typed_secrets: &[TypedSecret],
) -> Result<()> {
    for secret in typed_secrets {
        if typed_secrets
            .iter()
            .filter(|other| other.at_ms == secret.at_ms)
            .count()
            > 1
        {
            anyhow::bail!(
                "the contract `{}` takes only one secret per placeholder offset — \
                 two are typed at {} ms",
                contract.name,
                secret.at_ms
            );
        }
        if secret.text.chars().any(char::is_control) {
            anyhow::bail!(
                "the secret typed at {} ms is not a single line of text — \
                 a typed secret carries no control characters that would \
                 split it across the terminal",
                secret.at_ms
            );
        }
        let placeholder = contract.interactions.iter().find(|interaction| {
            interaction.at_ms == secret.at_ms
                && matches!(
                    interaction.kind,
                    InteractionKind::Input {
                        text: ScriptedInput::ByteCount { .. }
                    }
                )
        });
        match placeholder.map(|interaction| &interaction.kind) {
            Some(InteractionKind::Input {
                text: ScriptedInput::ByteCount { bytes },
            }) if *bytes == secret.text.len() as u64 => {}
            Some(InteractionKind::Input {
                text: ScriptedInput::ByteCount { bytes },
            }) => anyhow::bail!(
                "the secret typed at {} ms is {} bytes; the contract `{}` declares {bytes} — \
                 a typed secret must match its placeholder's count",
                secret.at_ms,
                secret.text.len(),
                contract.name
            ),
            _ => anyhow::bail!(
                "the contract `{}` declares no byte-count placeholder at {} ms — \
                 a typed secret must match a declared one",
                contract.name,
                secret.at_ms
            ),
        }
    }
    Ok(())
}

/// Capture a scenario run with the contract's declared secrets at hand:
/// each byte-count placeholder whose `at_ms` carries a matching typed
/// secret is typed at its offset; the rest of the contract runs exactly
/// as [`capture_scenario`] would.
pub fn capture_scenario_with_secrets(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
    typed_secrets: &[TypedSecret],
    now: u64,
) -> Result<ScenarioCapture> {
    validate_typed_secrets(contract, typed_secrets)?;
    // The standing preflight line: a missing Wine fails by name here,
    // before a run dir is touched or a process exists to hang.
    wine.preflight_wine()?;
    observe_run(program, run_dir, contract, wine, typed_secrets, now)
}

#[cfg(unix)]
fn observe_run(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
    typed_secrets: &[TypedSecret],
    now: u64,
) -> Result<ScenarioCapture> {
    let program_bytes = std::fs::read(program).with_context(|| {
        format!(
            "the scenario's program could not be read: {}",
            program.display()
        )
    })?;
    let pairing = CapturePairing {
        program_sha256: sha256_hex(&program_bytes),
        wine_version: wine.wine_version()?,
        // The normalization version in force at capture time: the compare
        // side refuses to pair captures across versions, and it can only
        // name versions the captures themselves carry.
        normalization_version: contract.normalization.version.clone(),
    };

    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("the run dir could not be created: {}", run_dir.display()))?;
    let wine_program = wine.to_wine_path(program)?;

    let before = files::snapshot_paths(run_dir, &contract.observation_paths);

    // Launch: the program under Wine, on a host PTY, in the contract's
    // working dir with the contract's explicit environment — nothing
    // inherited. The ownership token binds at launch.
    let mut console = pty::Pty::open(contract.cols, contract.rows)?;
    // The opening geometry is read off the live terminal, not taken from
    // the declaration: if the read ever fails the field stays absent and
    // the capture reads unassessed, never a claimed size it didn't see.
    let opening_geometry = console.geometry().ok();
    let (stdin_handle, stdout_handle, stderr_handle) = console.child_stdio()?;
    let mut command = std::process::Command::new(wine.wine_binary());
    command
        .arg(&wine_program)
        .args(&contract.argv)
        .current_dir(run_dir)
        .env_clear()
        .env("WINEDEBUG", "-all");
    // Wine's own toolchain environment (where the prefix and display
    // live) — the program's declared env is applied over it, and nothing
    // else is inherited. The prefix is the runner's, not the process
    // env's: a runner pointed at a private prefix runs its guests there,
    // and they land on that prefix's wineserver — the tree the sampler
    // then walks belongs to this run alone.
    command.env("WINEPREFIX", wine.prefix());
    for key in ["HOME", "DISPLAY", "XAUTHORITY", "USER"] {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    command
        .envs(&contract.env)
        .stdin(stdin_handle)
        .stdout(stdout_handle)
        .stderr(stderr_handle);
    let child = command.spawn().with_context(|| {
        format!(
            "the scenario run could not launch: {} under {}",
            program.display(),
            wine.wine_binary()
        )
    })?;
    let sample = ProcessSample {
        pid: child.id(),
        name: program
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| program.display().to_string()),
    };
    let mut process = OwnedProcess::own(child);
    console.close_slave();

    // The bounded event loop: interactions fire at their offsets while
    // the run stands, output is recorded under the cap, and each named
    // window (max run, idle) closes the run through the grace.
    let start = Instant::now();
    let max_run = Duration::from_millis(contract.max_run_ms);
    let idle_window = Duration::from_millis(contract.idle_timeout_ms);
    let grace = Duration::from_millis(contract.finalization_grace_ms);
    let mut samples = vec![sample];
    // The process dimension is sampled, not just declared: the sampler
    // anchors its sweeps to the processes this run brings into the world.
    #[cfg(target_os = "linux")]
    let mut sampler = sampler::Sampler::new(wine.prefix());
    let mut pending: VecDeque<&ScriptedInteraction> = contract.interactions.iter().collect();
    let mut terminal = Recording::new(contract.max_output_bytes);
    terminal.geometry = opening_geometry;
    let mut acknowledged_at_ms = Vec::new();
    let mut last_output = start;
    let (disposition, exit_code, finalization) = loop {
        if let Ok(Some(status)) = process.try_wait() {
            // Natural exit: one bounded drain so the last words are not
            // lost, then the run is *exited* with its code. Nothing was
            // finalized — the record leaves that field unassessed.
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (
                ExitDisposition::Exited,
                status.code().and_then(|code| u32::try_from(code).ok()),
                None,
            );
        }
        let elapsed = start.elapsed();
        if elapsed >= max_run {
            let filed = finalize_closed_run(&mut process, grace);
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (ExitDisposition::Timeout, None, Some(filed));
        }
        if last_output.elapsed() >= idle_window {
            let filed = finalize_closed_run(&mut process, grace);
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (ExitDisposition::IdleTimeout, None, Some(filed));
        }
        #[cfg(target_os = "linux")]
        sampler.sweep(elapsed, &mut samples);
        let elapsed_ms = elapsed.as_millis() as u64;
        while let Some(next) = pending.front().copied() {
            if next.at_ms > elapsed_ms {
                break;
            }
            pending.pop_front();
            let typed = typed_secrets
                .iter()
                .find(|secret| secret.at_ms == next.at_ms);
            if deliver(&console, next, typed.map(|secret| secret.text.as_str())) {
                acknowledged_at_ms.push(next.at_ms);
                // A resize that landed is proven by reading the geometry
                // back off the live terminal — the rendered state, not
                // the declared one.
                if matches!(next.kind, InteractionKind::Resize { .. })
                    && let Ok(state) = console.geometry()
                {
                    terminal.rendered_states.push(state);
                }
            }
        }
        if console
            .output_ready(20)
            .context("the scenario PTY failed while waiting for output")?
        {
            match console
                .read_output()
                .context("the scenario PTY failed while reading output")?
            {
                Some(bytes) => {
                    terminal.record(&bytes);
                    last_output = Instant::now();
                }
                None => continue,
            }
        }
    };

    // One last sweep after the close: a child born while the windows
    // ruled is sampled even if the cadence had not come round.
    #[cfg(target_os = "linux")]
    sampler.final_sweep(&mut samples);

    let after = files::snapshot_paths(run_dir, &contract.observation_paths);
    Ok(ScenarioCapture {
        scenario: contract.name.clone(),
        filed_at: now,
        pairing: Some(pairing),
        terminal: Some(terminal.into_observation()),
        interaction: Some(InteractionObservation { acknowledged_at_ms }),
        exit: Some(ExitObservation {
            disposition,
            exit_code,
            finalization,
        }),
        filesystem: Some(FilesystemObservation {
            entries: files::classify_paths(&contract.observation_paths, &before, &after),
        }),
        process: Some(ProcessObservation { samples }),
    })
}

#[cfg(not(unix))]
fn observe_run(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
    typed_secrets: &[TypedSecret],
    now: u64,
) -> Result<ScenarioCapture> {
    let _ = (program, run_dir, contract, wine, typed_secrets, now);
    anyhow::bail!("a scenario run drives its host PTY on unix hosts only")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    files::hex_digest(&hasher.finalize())
}

/// Close a run the windows ended, through the standing finalization
/// gate: SIGTERM past the ownership token's recheck, the declared grace
/// to end on its own, then the forced SIGKILL — never a bare-PID kill.
/// The gate's answer is filed into the capture by name, including the
/// token's refusal to touch a pid that answers to a stranger.
#[cfg(unix)]
fn finalize_closed_run(process: &mut OwnedProcess, grace: Duration) -> FinalizationOutcome {
    FinalizationOutcome::from(process.stop_with_grace(grace))
}

impl From<Stopped> for FinalizationOutcome {
    fn from(outcome: Stopped) -> Self {
        match outcome {
            Stopped::Signaled => Self::Signaled,
            Stopped::AlreadyExited => Self::AlreadyExited,
            Stopped::StaleIdentityUntouched => Self::StaleIdentityUntouched,
        }
    }
}

/// Deliver one interaction onto the terminal; true when it was delivered
/// while the run stood. A byte-count placeholder holds no text and types
/// nothing of its own — it is typeable only in its declared secret's
/// typed form, already validated against its count before the launch:
/// the fixture's `secret` command first, then the secret's line, one
/// write so nothing sits half-typed. A run in this lane types without
/// echo (measured: wine-11 conhost stops echoing once the guest console
/// clears `ENABLE_ECHO_INPUT`), so a typed secret never rides the output
/// stream.
#[cfg(unix)]
fn deliver(
    console: &pty::Pty,
    interaction: &ScriptedInteraction,
    typed_secret: Option<&str>,
) -> bool {
    match &interaction.kind {
        InteractionKind::Input {
            text: ScriptedInput::Text(text),
        } => {
            let mut bytes = text.as_bytes().to_vec();
            bytes.extend_from_slice(INPUT_LINE_END);
            console.write_input(&bytes).is_ok()
        }
        InteractionKind::Input {
            text: ScriptedInput::ByteCount { .. },
        } => {
            let Some(secret) = typed_secret else {
                return false;
            };
            let mut bytes = b"secret".to_vec();
            bytes.extend_from_slice(INPUT_LINE_END);
            bytes.extend_from_slice(secret.as_bytes());
            bytes.extend_from_slice(INPUT_LINE_END);
            console.write_input(&bytes).is_ok()
        }
        InteractionKind::Resize { cols, rows } => console.resize(*cols, *rows).is_ok(),
        InteractionKind::Signal { signal } => match signal {
            ScenarioSignal::Interrupt => console.write_input(b"\x03").is_ok(),
            ScenarioSignal::Break => console.write_input(b"\x1c").is_ok(),
        },
    }
}

/// Read out the console for a bounded window after the run stopped,
/// recording under the cap; whatever the pipe still holds is caught,
/// and an already-capped capture keeps draining without storing.
#[cfg(unix)]
fn drain(console: &pty::Pty, terminal: &mut Recording, window: Duration) {
    let until = Instant::now() + window;
    while Instant::now() < until {
        match console.output_ready(20) {
            Ok(true) => match console.read_output() {
                Ok(Some(bytes)) => terminal.record(&bytes),
                Ok(None) => break,
                Err(_) => break,
            },
            _ => continue,
        }
    }
}

/// Output recording under the cap: chunks stay whole until the cap is
/// reached, the crossing chunk is stored (at a character boundary) to
/// fill the cap exactly, and from there the capture states its
/// truncation and keeps draining. The accounting weighs the stored
/// bytes — the lossy-rendered chunk — not the raw read, so the capture
/// can never claim more than it holds, whatever codepoints straddle the
/// boundary.
struct Recording {
    chunks: Vec<String>,
    recorded_bytes: usize,
    cap: usize,
    capped: bool,
    /// Geometry read off the live terminal when it opened — absent only
    /// if the read failed, which reads unassessed.
    geometry: Option<TerminalGeometry>,
    /// Geometries read back off the live terminal after each acknowledged
    /// resize, in order — proof the resizes landed on the rendering.
    rendered_states: Vec<TerminalGeometry>,
}

impl Recording {
    fn new(cap: u64) -> Self {
        Self {
            chunks: Vec::new(),
            recorded_bytes: 0,
            cap: cap as usize,
            capped: false,
            geometry: None,
            rendered_states: Vec::new(),
        }
    }

    fn record(&mut self, bytes: &[u8]) {
        if self.capped || bytes.is_empty() {
            return;
        }
        let rendered = String::from_utf8_lossy(bytes).into_owned();
        let room = self.cap - self.recorded_bytes;
        if rendered.len() <= room {
            self.recorded_bytes += rendered.len();
            self.chunks.push(rendered);
            if self.recorded_bytes == self.cap {
                self.capped = true;
            }
        } else {
            let mut end = room;
            while !rendered.is_char_boundary(end) {
                end -= 1;
            }
            self.chunks.push(rendered[..end].to_string());
            self.recorded_bytes = self.cap;
            self.capped = true;
        }
    }

    fn into_observation(self) -> TerminalObservation {
        TerminalObservation {
            chunks: self.chunks,
            output_capped: self.capped,
            cap_bytes: self.capped.then_some(self.cap as u64),
            geometry: self.geometry,
            rendered_states: self.rendered_states,
        }
    }
}

#[cfg(test)]
mod tests;
