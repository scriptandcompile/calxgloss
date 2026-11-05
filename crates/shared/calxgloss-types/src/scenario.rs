//! The scenario records — the shared shapes of the P24 scenario-capture
//! lane (glossary: *scenario contract*, *scenario run*).
//!
//! A **scenario contract** declares how one EXE target binary is to be run:
//! working dir, explicit env, argv, scripted interactions, terminal
//! geometry, filesystem observation paths, timing windows, output caps,
//! versioned normalization rules, and a finalization grace. Interface owns
//! the contract's authorship; pipeline and testgen only read it.
//!
//! A **scenario capture** is what one scenario run was observed to do:
//! blocks per dimension (terminal, interaction, exit, filesystem,
//! process), each filed by the capture slice that produces it (that slice
//! adds the *scenario capture* name to the glossary). A **scenario
//! verdict** compares two captures under the contract, one closed
//! [`DimensionVerdict`] per dimension.
//!
//! The honesty rule every record here obeys: absent fields read
//! *unassessed*. Silence is never a pass and never a fail — a dimension
//! nobody observed states its non-observation, exactly as the absent-field
//! rule ADR-0053 established for unknowns.
//!
//! Note the collision rule the pipeline glossary states: a scenario *run*
//! is one child execution of the target program — never the run-wide *Run*.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::TypesError;
use crate::identity::BinaryIdentity;

#[cfg(test)]
mod tests;

/// The farthest-out window a scenario timing field may declare: a run
/// window beyond a day is a declaration mistake, refused at declare time
/// rather than waited on (issue #402).
pub const MAX_SCENARIO_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

/// The longest finalization grace a contract may declare between SIGTERM
/// and SIGKILL. Past this, a run is not being finalized — it is being
/// indulged.
pub const MAX_FINALIZATION_GRACE_MS: u64 = 5 * 60 * 1_000;

/// The largest terminal-output cap a contract may declare. A capture
/// records at most this many bytes per scenario run.
pub const MAX_SCENARIO_OUTPUT_BYTES: u64 = 256 * 1024 * 1024;

/// A validation refusal naming the offending field and what is wrong
/// with it.
fn invalid(field: &str, reason: impl Into<String>) -> TypesError {
    TypesError::ScenarioFieldInvalid {
        field: field.into(),
        reason: reason.into(),
    }
}

/// The closed per-dimension verdict of a scenario comparison: a dimension
/// was either assessed and passed, assessed and failed, or nobody assessed
/// it. There is no fourth state and no silent default toward pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionVerdict {
    /// The dimension was compared and the two sides agreed.
    AssessedPass,
    /// The dimension was compared and diverged; the divergence is named
    /// field-by-field beside the verdict.
    AssessedFail,
    /// Nothing was assessed on this dimension — silence, filed as itself.
    /// An absent field deserializes to this state, never the other two.
    #[default]
    Unassessed,
}

/// The scenario comparison verdict: one [`DimensionVerdict`] per dimension
/// of the five (terminal, interaction, exit, filesystem, process). Filed
/// as its own digest-bearing document by the comparator slice (P24.6);
/// this slice grows the shape.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct ScenarioVerdict {
    /// What the comparison said about the terminal dimension.
    pub terminal: DimensionVerdict,
    /// What the comparison said about the interaction dimension.
    pub interaction: DimensionVerdict,
    /// What the comparison said about the exit dimension.
    pub exit: DimensionVerdict,
    /// What the comparison said about the filesystem dimension.
    pub filesystem: DimensionVerdict,
    /// What the comparison said about the process dimension.
    pub process: DimensionVerdict,
}

/// One field where the two *scenario captures* diverged, named with both
/// sides beside it — the reviewer never hand-diffs two raw captures to
/// find what the comparison disagreed on. A missing side reads `None`:
/// one capture carries the segment, ack, row, or entry the other never had.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionDivergence {
    /// One normalized terminal output segment reads differently, named by
    /// its segment index; `None` is the side that never produced it.
    TerminalSegment {
        /// The zero-based segment (chunk) index where the sides disagree.
        index: usize,
        /// The left side's normalized segment text, if it has one.
        left: Option<String>,
        /// The right side's normalized segment text, if it has one.
        right: Option<String>,
    },
    /// The opening terminal geometries the two runs measured disagree —
    /// `None` is the side that never read its geometry.
    TerminalGeometry {
        /// The left side's measured opening geometry, if it has one.
        left: Option<TerminalGeometry>,
        /// The right side's measured opening geometry, if it has one.
        right: Option<TerminalGeometry>,
    },
    /// The *rendered states* read back after resizes disagree: a restitch
    /// whose resize never landed on the terminal shows up right here.
    TerminalRenderedStates {
        /// The left side's rendered states, in order.
        left: Vec<TerminalGeometry>,
        /// The right side's rendered states, in order.
        right: Vec<TerminalGeometry>,
    },
    /// One scripted interaction offset was acknowledged on one side only,
    /// named by its at-offset.
    InteractionAcknowledgement {
        /// The at-offset one side acknowledged and the other did not.
        at_ms: u64,
        /// Whether the left side acknowledged this offset.
        left: bool,
        /// Whether the right side acknowledged this offset.
        right: bool,
    },
    /// The two runs ended by different named dispositions.
    ExitDisposition {
        /// How the left run ended.
        left: ExitDisposition,
        /// How the right run ended.
        right: ExitDisposition,
    },
    /// The exit codes disagree — `None` is the side that never reported
    /// a code, itself a named difference.
    ExitCode {
        /// The left side's exit code, if it reported one.
        left: Option<u32>,
        /// The right side's exit code, if it reported one.
        right: Option<u32>,
    },
    /// The finalization outcomes disagree — including one side having
    /// finalized and the other never having been finalized at all.
    ExitFinalization {
        /// The left side's finalization outcome, if the run was finalized.
        left: Option<FinalizationOutcome>,
        /// The right side's finalization outcome, if the run was finalized.
        right: Option<FinalizationOutcome>,
    },
    /// One declared observation path reads differently across the two
    /// captures — the whole entry sits on each side, so the change kind,
    /// size, digest, and block digests are all beside the reader.
    FileSystemPath {
        /// The declared observation path that disagrees.
        path: String,
        /// The left side's entry for this path, if it has one.
        left: Option<FileObservation>,
        /// The right side's entry for this path, if it has one.
        right: Option<FileObservation>,
    },
    /// One *process-tree row* one side had and the other did not — a
    /// child one program spawned and the other never did. `None` names
    /// the side that never sighted the row.
    ProcessTreeRow {
        /// The left side's row, if it sighted it.
        left: Option<ProcessSample>,
        /// The right side's row, if it sighted it.
        right: Option<ProcessSample>,
    },
}

/// The filed document of one *scenario comparison*: two *scenario captures*
/// judged under one *scenario contract*, one [`DimensionVerdict`] per
/// dimension of the five, every [`DimensionDivergence`] named with both
/// sides beside it, and the residual unknowns that block a
/// complete-equivalence claim stated by name. The comparator (P24.6) files
/// it at `re/scenarios/verdicts/<binary identity>-<scenario key>.json` as
/// its own digest-bearing document: [`Self::content_digest`] names the
/// content, so P25's receipts and P26's ledger cite a verdict by digest
/// and any reader proves the citation from the filed bytes alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScenarioVerdictDocument {
    /// The target binary identity this verdict was filed for.
    pub binary: BinaryIdentity,
    /// The scenario name whose captures were compared.
    pub scenario: String,
    /// When the verdict was filed, as a Unix timestamp in seconds.
    pub filed_at: u64,
    /// The normalization version the pair was judged under — stated, never
    /// silent; a pair across different versions is refused, never filed.
    pub normalization_version: String,
    /// The content digest of the left capture document the comparison read.
    pub left_capture_sha256: String,
    /// The content digest of the right capture document the comparison read.
    pub right_capture_sha256: String,
    /// The left capture's pairing stamps, beside the reader so what paired
    /// against what is always visible — absent reads unstamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_pairing: Option<CapturePairing>,
    /// The right capture's pairing stamps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_pairing: Option<CapturePairing>,
    /// The five dimensions' states.
    pub verdict: ScenarioVerdict,
    /// Every named divergence, in dimension order (terminal, interaction,
    /// exit, filesystem, process) and capture order within a dimension.
    pub divergences: Vec<DimensionDivergence>,
    /// What stays unknown even in this comparison — the output caps that
    /// fired, the files outside the observation paths, a mismatched Wine
    /// version — each stated, each blocking a complete-equivalence claim.
    pub residual_unknowns: Vec<String>,
    /// Whether the pair proves complete equivalence: only ever true when
    /// every dimension assessed pass and no residual unknown stands; the
    /// honesty rule means a bounded capture never silently claims it.
    pub claims_complete_equivalence: bool,
    /// The digest of this document's content (see [`Self::content_digest`]);
    /// receipts cite the verdict by it.
    pub digest: String,
}

impl ScenarioVerdictDocument {
    /// The canonical digest of this verdict's content: sha256 over the
    /// document's own JSON with the `digest` field blanked, prefixed
    /// `sha256:` like every other content digest the record tree carries.
    /// The digest field never rides its own digest, so a reader of a filed
    /// document re-derives the same value from the filed bytes alone.
    pub fn content_digest(&self) -> Result<String, TypesError> {
        use sha2::{Digest as _, Sha256};
        let mut blanked = self.clone();
        blanked.digest = String::new();
        let bytes = serde_json::to_vec(&blanked)?;
        let sum = Sha256::digest(&bytes);
        let hex: String = sum.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(format!("sha256:{hex}"))
    }
}

/// How a scenario run ended, from the closed set the capture lane names.
/// Every way a run stops has a name here; nothing stops anonymously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitDisposition {
    /// The program exited on its own; the exit code accompanies it.
    Exited,
    /// The max-run-duration window closed the run.
    Timeout,
    /// The idle-timeout window closed the run.
    IdleTimeout,
    /// The operator cancelled the run.
    Cancelled,
    /// The run could not proceed at all (launch or scaffold failure).
    Failed,
}

/// The pairing stamps beside one capture: which program bytes ran and which
/// Wine ran them. A capture pairs for comparison only against identical
/// program bytes; a digest mismatch is a stated mismatch, never silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CapturePairing {
    /// sha256 of the program's file content the capture ran.
    pub program_sha256: String,
    /// The Wine version that ran the program.
    pub wine_version: String,
    /// The normalization version the governing contract declared at
    /// capture time: two captures never pair for comparison across
    /// different versions. A capture filed before this stamp existed
    /// deserializes with no version — unstamped means not proven, and
    /// the compare side refuses the pair naming that, never assuming
    /// agreement.
    #[serde(default)]
    pub normalization_version: String,
}

/// How a finalization — the close of a run that did not end on its own —
/// reached its process, through the ownership token's SIGTERM→grace→
/// SIGKILL gate. The closed set the owned-process discipline can name;
/// every scenario close lands one of these in its record, including a
/// token that refused to touch a recycled pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizationOutcome {
    /// The token rechecked clean and the owned process was signaled —
    /// ended by SIGTERM inside the grace or forced by SIGKILL after it.
    Signaled,
    /// The process had already exited before any signal: nothing to
    /// finalize, and nothing was signaled.
    AlreadyExited,
    /// The pid answered to a different identity than the token bound:
    /// the token refused, the stranger was never touched, and this
    /// record is how the capture says so.
    StaleIdentityUntouched,
}

/// The exit dimension's block: how the run ended and with what code, when
/// a code exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ExitObservation {
    /// The named way the run ended. An exit block without a disposition
    /// is a shape error, not a reading — a run that ended names how.
    pub disposition: ExitDisposition,
    /// The exit code, when the disposition carries one.
    #[serde(default)]
    pub exit_code: Option<u32>,
    /// How the finalization gate answered for a run the windows closed;
    /// absent when the run exited on its own — nothing was finalized, so
    /// the field reads *unassessed* like every absent block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization: Option<FinalizationOutcome>,
}

/// The rendered terminal's size in cells — geometry, not bytes. The run
/// records it measured off the live terminal, never as declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TerminalGeometry {
    /// Columns (character cells) wide.
    pub cols: u16,
    /// Rows (character cells) tall.
    pub rows: u16,
}

/// The terminal dimension's block: the raw output chunks in order, plus
/// the cap's explicit truncation mark. A capped capture states its cap —
/// it never claims more than it saw.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct TerminalObservation {
    /// Raw output chunks, in the order the console produced them.
    pub chunks: Vec<String>,
    /// Set when the output cap stopped recording; the run produced more.
    pub output_capped: bool,
    /// The cap the recording stopped at, named in the record only when
    /// it fired — a capped capture states its cap, so a reader of the
    /// document alone knows exactly what was withheld.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_bytes: Option<u64>,
    /// The geometry the live terminal opened at, read back off the host
    /// PTY — absent reads unassessed, never a defaulted size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geometry: Option<TerminalGeometry>,
    /// Every geometry the live terminal rendered after a resize, in order,
    /// each read back off the running terminal rather than echoed from the
    /// declared interaction — proof the resize landed on the terminal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rendered_states: Vec<TerminalGeometry>,
}

/// The interaction dimension's block: which scripted interactions the run
/// acknowledged, by their at-offsets.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct InteractionObservation {
    /// The `at_ms` offsets of interactions the run acknowledged.
    pub acknowledged_at_ms: Vec<u64>,
}

/// How one declared observation path changed across the scenario run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChange {
    /// The path did not exist before the run and did after.
    Created,
    /// The path existed before the run and did not after.
    Deleted,
    /// The path existed on both sides with different content.
    Modified,
    /// The path existed on both sides with identical content.
    Unchanged,
}

/// One declared observation path and how the run changed it, with the
/// content identity the comparator weighs: the whole-file digest plus
/// the 4 KiB block digests of the same bytes (P24.3), so a partial write
/// shows exactly which blocks moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FileObservation {
    /// The declared path, relative to the run dir.
    pub path: String,
    /// How the run changed it.
    pub change: FileChange,
    /// Content size at the named side, when that side exists.
    pub size_bytes: Option<u64>,
    /// Whole-file sha256 of the named side: the after side for created,
    /// modified, and unchanged, the before side for a deleted path.
    pub sha256: Option<String>,
    /// The 4 KiB block digests of those same bytes, in block order; the
    /// last block is the short remainder's digest. Empty only when no
    /// side exists or the document predates the block hashes.
    #[serde(default)]
    pub block_hashes: Vec<String>,
}

/// The filesystem dimension's block: the before/after classification of
/// the contract's observation paths. Files outside those paths are
/// honestly unknown, stated as such.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct FilesystemObservation {
    /// One entry per declared observation path.
    pub entries: Vec<FileObservation>,
}

/// One sampled process-tree row: a program the scenario run (or one of its
/// children) had running when the sample was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProcessSample {
    /// The process id the sample saw.
    pub pid: u32,
    /// The program name it was running.
    pub name: String,
}

/// The process dimension's block: the *process samples* — the launch
/// sample plus the ones swept from the run's live process tree, so a
/// program that spawns children shows them in the record. A child-free
/// run records its honest emptiness, not a gap.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct ProcessObservation {
    /// The samples in filing order: the launch sample first, then each
    /// sweep's newly sighted pids in pid order.
    pub samples: Vec<ProcessSample>,
}

/// What one scenario run of one program was observed to do, block per
/// dimension. The capture slices (P24.3 onward) fill the blocks in; an
/// absent block reads *unassessed* at compare time — silence is readable,
/// never a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScenarioCapture {
    /// The scenario name this capture ran.
    pub scenario: String,
    /// When the capture was filed, as a Unix timestamp in seconds.
    pub filed_at: u64,
    /// The pairing stamps, when the run got far enough to carry them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing: Option<CapturePairing>,
    /// The terminal dimension's block, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<TerminalObservation>,
    /// The interaction dimension's block, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interaction: Option<InteractionObservation>,
    /// The exit dimension's block, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitObservation>,
    /// The filesystem dimension's block, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FilesystemObservation>,
    /// The process dimension's block, when observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessObservation>,
}

/// One scripted interaction the scenario types into the run, at an offset
/// from the run's start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScriptedInteraction {
    /// Milliseconds from the start of the scenario run.
    pub at_ms: u64,
    /// What happens at that offset.
    pub kind: InteractionKind,
}

/// What the scenario does at an interaction offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionKind {
    /// Type text into the run's console input. A sensitive input never
    /// persists its text: it files as a byte-count placeholder instead,
    /// and the capture proves the secret appears nowhere in its bytes.
    Input { text: ScriptedInput },
    /// Resize the console to this geometry.
    Resize { cols: u16, rows: u16 },
    /// Send this signal to the scenario run (never a bare-PID kill: the
    /// ownership token governs every finalization signal).
    Signal { signal: ScenarioSignal },
}

/// A scripted input's stored form: the text itself, or a byte-count
/// placeholder where the input was declared sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptedInput {
    /// The literal text to type.
    Text(String),
    /// A sensitive input's placeholder: how many bytes were typed, never
    /// which ones.
    ByteCount { bytes: u64 },
}

/// The closed set of signals a scenario run may receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioSignal {
    /// The console interrupt (Ctrl-C).
    Interrupt,
    /// The console break (Ctrl-Break).
    Break,
}

/// One declared literal replacement a normalization applies to captured
/// output before comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LiteralReplacement {
    /// The literal text to find.
    pub from: String,
    /// What it becomes.
    pub to: String,
}

/// The contract's declared output normalization: only these rules ever
/// apply, and the version they carry is stated in every comparison so two
/// captures normalized under different versions never pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NormalizationRules {
    /// The version of the normalization rule set in force.
    pub version: String,
    /// Literal replacements, applied in declaration order.
    #[serde(default)]
    pub literal_replacements: Vec<LiteralReplacement>,
    /// Port-number patterns masked out of comparison.
    #[serde(default)]
    pub port_patterns: Vec<String>,
}

/// The scenario contract: the closed declaration of how one EXE target
/// binary is run for one scenario (glossary: *scenario contract*).
///
/// Interface owns the contract's authorship; pipeline and testgen only
/// read what was filed. The content is closed to this list — anything else
/// a run could do is not declarable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScenarioContract {
    /// The scenario name this contract declares, unique per target binary.
    pub name: String,
    /// The working dir the scenario run starts in.
    pub working_dir: String,
    /// The explicit environment the run gets — nothing is inherited.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The argv (after the program itself) the scenario run receives.
    #[serde(default)]
    pub argv: Vec<String>,
    /// The scripted interactions, in at-offset order.
    #[serde(default)]
    pub interactions: Vec<ScriptedInteraction>,
    /// The console geometry the run starts with.
    pub cols: u16,
    /// The console rows the run starts with.
    pub rows: u16,
    /// The declared filesystem observation paths, relative to the run dir.
    #[serde(default)]
    pub observation_paths: Vec<String>,
    /// The idle-timeout window that ends a silent run, in ms.
    pub idle_timeout_ms: u64,
    /// The max run duration that ends any run, in ms.
    pub max_run_ms: u64,
    /// The SIGTERM→SIGKILL grace before finalization forces, in ms.
    pub finalization_grace_ms: u64,
    /// The cap on recorded terminal output, in bytes.
    pub max_output_bytes: u64,
    /// The declared, versioned output normalization in force.
    pub normalization: NormalizationRules,
}

impl ScenarioContract {
    /// Validate this contract against the rules a declare path enforces:
    /// every refusal names the offending field so the operator knows what
    /// to fix, and nothing files on a refusal.
    ///
    /// `validation_root` resolves a relative `working_dir`. Observation
    /// paths are checked lexically — the run dir they live in is created
    /// at capture time — so a path that is absolute or climbs with `..`
    /// escapes the run dir by construction and is refused. Timing fields
    /// are refused at the absurd bound, not waited on.
    pub fn validate(&self, validation_root: &Path) -> Result<(), TypesError> {
        if self.name.is_empty() {
            return Err(invalid("scenario", "a scenario needs a name"));
        }
        let working_dir = Path::new(&self.working_dir);
        let resolved = if working_dir.is_absolute() {
            working_dir.to_path_buf()
        } else {
            validation_root.join(working_dir)
        };
        if !resolved.is_dir() {
            return Err(invalid(
                "working_dir",
                format!("does not resolve to a directory: {}", resolved.display()),
            ));
        }
        if self.cols == 0 {
            return Err(invalid("cols", "the console needs at least one column"));
        }
        if self.rows == 0 {
            return Err(invalid("rows", "the console needs at least one row"));
        }
        for path in &self.observation_paths {
            let candidate = Path::new(path);
            if candidate.is_absolute()
                || candidate
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
            {
                return Err(invalid(
                    "observation_paths",
                    format!(
                        "`{path}` escapes the run dir; observation paths are relative and never climb"
                    ),
                ));
            }
        }
        if self.idle_timeout_ms == 0 || self.idle_timeout_ms > MAX_SCENARIO_WINDOW_MS {
            return Err(invalid(
                "idle_timeout_ms",
                format!("must be between 1 and {MAX_SCENARIO_WINDOW_MS} ms"),
            ));
        }
        if self.max_run_ms == 0 || self.max_run_ms > MAX_SCENARIO_WINDOW_MS {
            return Err(invalid(
                "max_run_ms",
                format!("must be between 1 and {MAX_SCENARIO_WINDOW_MS} ms"),
            ));
        }
        if self.idle_timeout_ms > self.max_run_ms {
            return Err(invalid(
                "idle_timeout_ms",
                "the idle window outlasts the max run duration it lives inside",
            ));
        }
        if self.finalization_grace_ms == 0 || self.finalization_grace_ms > MAX_FINALIZATION_GRACE_MS
        {
            return Err(invalid(
                "finalization_grace_ms",
                format!("must be between 1 and {MAX_FINALIZATION_GRACE_MS} ms"),
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_SCENARIO_OUTPUT_BYTES {
            return Err(invalid(
                "max_output_bytes",
                format!("must be between 1 and {MAX_SCENARIO_OUTPUT_BYTES} bytes"),
            ));
        }
        for interaction in &self.interactions {
            if interaction.at_ms >= self.max_run_ms {
                return Err(invalid(
                    "interactions",
                    format!(
                        "an interaction at {} ms can never fire: the run window closes at {} ms",
                        interaction.at_ms, self.max_run_ms
                    ),
                ));
            }
        }
        if self.normalization.version.trim().is_empty() {
            return Err(invalid(
                "normalization",
                "normalization rules must carry the version in force",
            ));
        }
        Ok(())
    }
}

/// The record tree's scenario-contract document for one target binary:
/// every declared scenario contract for that binary, filed as
/// `re/scenarios/<binary identity>.json` — the interface-owned document
/// (pipeline and testgen only read it), exactly one document with exactly
/// one owner, keyed by binary identity.
///
/// Re-declaring a scenario replaces its contract inside the document, so
/// the binary keeps exactly one current contract per scenario name;
/// several scenarios per binary coexist as separate map entries. Like the
/// unknown ledger's, the filing envelope names which binary the document
/// was filed for and when, so a reader can tell a filed document from a
/// stray one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScenarioContracts {
    /// The binary identity this document was filed for. A document without
    /// its envelope is not a filed contract set.
    pub binary: BinaryIdentity,
    /// When the document was filed, as a Unix timestamp in seconds.
    pub filed_at: u64,
    /// The current contracts, keyed by scenario name; `BTreeMap` keeps the
    /// filed document deterministic and diff-friendly.
    #[serde(default)]
    pub scenarios: BTreeMap<String, ScenarioContract>,
}

impl ScenarioContracts {
    /// Declare (or re-declare) `contract`: a new scenario name adds an
    /// entry; an existing name's contract is replaced outright — never
    /// merged or amended — so the binary keeps exactly one current
    /// contract per scenario name.
    ///
    /// The contract is validated against `validation_root` first: a
    /// refusal names its offending field and this changes nothing at all.
    /// `now` refreshes the filing envelope stamp only on success.
    pub fn declare(
        &mut self,
        contract: ScenarioContract,
        validation_root: &Path,
        now: u64,
    ) -> Result<(), TypesError> {
        contract.validate(validation_root)?;
        self.scenarios.insert(contract.name.clone(), contract);
        self.filed_at = now;
        Ok(())
    }
}

/// The record tree's scenario-contract directory: `re/scenarios/<workspace>`.
/// Interface owns the contract documents filed here, one per target binary;
/// pipeline and testgen only read them.
pub fn scenario_contracts_dir(workspace: impl AsRef<Path>) -> PathBuf {
    workspace.as_ref().join("re").join("scenarios")
}

/// The path of one binary's contract document:
/// `re/scenarios/<binary identity>.json`.
pub fn scenario_contracts_path(workspace: impl AsRef<Path>, binary: &BinaryIdentity) -> PathBuf {
    scenario_contracts_dir(workspace).join(format!("{binary}.json"))
}

/// The record tree's scenario-capture directory: `re/scenarios/captures`.
/// Interface files captures here, one document per (binary, scenario
/// name); compare and replay slices only read them.
pub fn scenario_captures_dir(workspace: impl AsRef<Path>) -> PathBuf {
    scenario_contracts_dir(workspace).join("captures")
}

/// The record tree location of one filed scenario capture:
/// `re/scenarios/captures/<binary identity>-<scenario key>.json` —
/// exactly one current capture per scenario name per binary: re-capture
/// replaces the previous document outright, never versioned, never appended.
///
/// The scenario name folds into a file key: every character outside
/// `[A-Za-z0-9._-]` folds to `-`, so no declared name can ever climb out
/// of the captures directory.
pub fn scenario_capture_path(
    workspace: impl AsRef<Path>,
    binary: &BinaryIdentity,
    scenario: &str,
) -> PathBuf {
    let key = scenario_file_key(scenario);
    scenario_captures_dir(workspace).join(format!("{binary}-{key}.json"))
}

/// The record tree's scenario-verdict directory: `re/scenarios/verdicts`.
/// The comparator slice files scenario verdicts here, one document per
/// (binary, scenario name); P25's receipts and P26's ledger only read them.
pub fn scenario_verdicts_dir(workspace: impl AsRef<Path>) -> PathBuf {
    scenario_contracts_dir(workspace).join("verdicts")
}

/// The record tree location of one filed scenario verdict:
/// `re/scenarios/verdicts/<binary identity>-<scenario key>.json` — the
/// scenario key folds exactly as the capture key does, and a re-compare
/// replaces the previous verdict document outright.
pub fn scenario_verdict_path(
    workspace: impl AsRef<Path>,
    binary: &BinaryIdentity,
    scenario: &str,
) -> PathBuf {
    let key = scenario_file_key(scenario);
    scenario_verdicts_dir(workspace).join(format!("{binary}-{key}.json"))
}

/// The file-key fold shared by the capture and verdict paths: every
/// character outside `[A-Za-z0-9._-]` folds to `-`, so no declared name
/// can ever climb out of its directory.
fn scenario_file_key(scenario: &str) -> String {
    scenario
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect()
}
