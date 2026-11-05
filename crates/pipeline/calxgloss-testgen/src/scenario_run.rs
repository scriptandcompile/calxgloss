//! The scenario-run seam (P24.3, issue #404): run one declared scenario
//! contract against the original target program under the standing Wine
//! toolchain rules and produce the observed **scenario capture** — exit
//! disposition, raw terminal chunks under the cap with its truncation
//! mark, the before/after classification of the declared observation
//! paths, the interaction acknowledgements, the launch sample, and the
//! pairing stamps (the program's sha256 and the Wine that ran it).
//!
//! The run binds an ownership token at launch; every finalization signal
//! rides the token-gated SIGTERM→SIGKILL grace. A missing Wine fails the
//! capture by name through the standing preflight line — before any
//! process exists to hang.
//!
//! This seam owns the *run*; the interface owns loading the contract,
//! filing the document, and the pairing-mismatch statement (compare the
//! CLI's scenario command). An absent capture block reads *unassessed* —
//! the honesty rule — but a run that reached the dimension always names
//! what it saw, and a capped capture never claims more than it saw.

mod files;
#[cfg(unix)]
mod pty;

use std::collections::VecDeque;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use calxgloss_types::{
    CapturePairing, ExitDisposition, ExitObservation, FilesystemObservation, InteractionKind,
    InteractionObservation, ProcessObservation, ProcessSample, ScenarioCapture, ScenarioContract,
    ScenarioSignal, ScriptedInput, ScriptedInteraction, TerminalObservation,
};

use crate::wine::WineRunner;
use crate::wine::owned::OwnedProcess;
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
    // The standing preflight line first: a missing Wine fails by name
    // here, before a run dir is touched or a process exists to hang.
    wine.preflight_wine()?;
    observe_run(program, run_dir, contract, wine, now)
}

#[cfg(unix)]
fn observe_run(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
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
    };

    std::fs::create_dir_all(run_dir)
        .with_context(|| format!("the run dir could not be created: {}", run_dir.display()))?;
    let wine_program = wine.to_wine_path(program)?;

    let before = files::snapshot_paths(run_dir, &contract.observation_paths);

    // Launch: the program under Wine, on a host PTY, in the contract's
    // working dir with the contract's explicit environment — nothing
    // inherited. The ownership token binds at launch.
    let mut console = pty::Pty::open(contract.cols, contract.rows)?;
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
    // else is inherited.
    for key in ["WINEPREFIX", "HOME", "DISPLAY", "XAUTHORITY", "USER"] {
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
    let mut pending: VecDeque<&ScriptedInteraction> = contract.interactions.iter().collect();
    let mut terminal = Recording::new(contract.max_output_bytes);
    let mut acknowledged_at_ms = Vec::new();
    let mut last_output = start;
    let (disposition, exit_code) = loop {
        if let Ok(Some(status)) = process.try_wait() {
            // Natural exit: one bounded drain so the last words are not
            // lost, then the run is *exited* with its code.
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (
                ExitDisposition::Exited,
                status.code().and_then(|code| u32::try_from(code).ok()),
            );
        }
        let elapsed = start.elapsed();
        if elapsed >= max_run {
            process.stop_with_grace(grace);
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (ExitDisposition::Timeout, None);
        }
        if last_output.elapsed() >= idle_window {
            process.stop_with_grace(grace);
            drain(&console, &mut terminal, Duration::from_millis(200));
            break (ExitDisposition::IdleTimeout, None);
        }
        let elapsed_ms = elapsed.as_millis() as u64;
        while let Some(next) = pending.front().copied() {
            if next.at_ms > elapsed_ms {
                break;
            }
            pending.pop_front();
            if deliver(&console, next) {
                acknowledged_at_ms.push(next.at_ms);
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
        }),
        filesystem: Some(FilesystemObservation {
            entries: files::classify_paths(&contract.observation_paths, &before, &after),
        }),
        process: Some(ProcessObservation {
            samples: vec![sample],
        }),
    })
}

#[cfg(not(unix))]
fn observe_run(
    program: &Path,
    run_dir: &Path,
    contract: &ScenarioContract,
    wine: &WineRunner,
    now: u64,
) -> Result<ScenarioCapture> {
    let _ = (program, run_dir, contract, wine, now);
    anyhow::bail!("a scenario run drives its host PTY on unix hosts only")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    files::hex_digest(&hasher.finalize())
}

/// Deliver one interaction onto the terminal; true when it was delivered
/// while the run stood — a byte-count placeholder's secret text is not
/// held here, so it is never delivered and never acknowledged.
#[cfg(unix)]
fn deliver(console: &pty::Pty, interaction: &ScriptedInteraction) -> bool {
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
        } => false,
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
}

impl Recording {
    fn new(cap: u64) -> Self {
        Self {
            chunks: Vec::new(),
            recorded_bytes: 0,
            cap: cap as usize,
            capped: false,
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
        }
    }
}

#[cfg(test)]
mod tests;
