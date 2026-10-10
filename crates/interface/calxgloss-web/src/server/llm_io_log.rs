//! Server-side LLM I/O log — the prompts and responses a live run emits,
//! persisted as append-only JSONL under `re/analysis/llm_io/` (issue #77).
//!
//! Until now the LLM I/O log existed only as a capped in-memory array in the
//! browser, fed by live WebSocket events — history was lost on every page
//! reload. This module makes the server the source of truth: the live event
//! consumer appends every `LlmRequest` / `LlmResponse` / `LlmCallFailed`
//! event as one JSONL line the moment it arrives, and `GET /api/llm-io`
//! serves the retained window back with its metadata and token counts.
//!
//! Growth is bounded: the log keeps at most [`MAX_LLM_IO_ENTRIES`] newest
//! entries. Appends past that cap stay cheap (one `write` per event); once
//! [`TRIM_MARGIN`] entries have piled on top of the cap, the file is
//! rewritten down to the newest [`MAX_LLM_IO_ENTRIES`] in one atomic
//! temp-file-and-rename, so readers never see a half-written log.

use calxgloss_types::{PersistError, ProgressEvent, analysis_dir};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tracing::{debug, warn};

/// Entries the log retains at most — the newest window of a live run's LLM
/// traffic. Prompts and responses are large (tens of KB each), so this cap
/// is deliberately far tighter than the run-telemetry logs' 10,000.
pub const MAX_LLM_IO_ENTRIES: usize = 500;

/// How far past [`MAX_LLM_IO_ENTRIES`] appends may run before the file is
/// rewritten down to the cap. Trimming on every append would rewrite the
/// whole file per event; this margin amortizes the rewrite across many
/// appends while keeping the on-disk file bounded at
/// `MAX_LLM_IO_ENTRIES + TRIM_MARGIN` lines.
const TRIM_MARGIN: usize = 100;

/// Monotonic counter keeping each rotation temp file name unique within this
/// process, mirroring the `save_json` convention in `calxgloss-types`.
static ROTATE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Which side of the exchange an entry captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LlmIoEntryType {
    /// The prompt sent to the LLM.
    Request,
    /// The raw content the LLM returned.
    Response,
    /// The call failed; `content` carries the error message.
    Error,
}

/// One persisted LLM request/response/error, with the metadata the log UI
/// filters and groups by (issue #80) and the token count when the event
/// carried one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmIoEntry {
    /// Which side of the exchange this entry is.
    #[serde(rename = "type")]
    pub entry_type: LlmIoEntryType,
    /// Binary the unit belongs to (verbatim filename).
    pub binary: String,
    /// Function being translated.
    pub function: String,
    /// Retry attempt the call belongs to.
    pub attempt: u32,
    /// Prompt strategy the attempt used.
    pub strategy: String,
    /// The prompt text, the response content, or the error message.
    pub content: String,
    /// Tokens the call consumed, when the event reported it (responses do,
    /// requests do not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_used: Option<usize>,
    /// Unix seconds when the entry was recorded, stamped internally.
    pub timestamp: u64,
}

/// Append-only JSONL log of a workspace's LLM I/O.
///
/// One writer (the live server's event consumer task) appends; HTTP handlers
/// read. The retained-entry count backs the rotation check; it is counted
/// lazily on the first append so a read-only caller (the endpoint) never
/// pays for it.
pub struct LlmIoLog {
    path: PathBuf,
    /// Entries currently in the file, or [`usize::MAX`] until the first
    /// append counts what a previous run left there.
    entries_in_file: AtomicUsize,
}

impl LlmIoLog {
    /// Point the log at `{workspace}/re/analysis/llm_io/log.jsonl`.
    pub fn new(workspace: impl AsRef<Path>) -> Self {
        Self {
            path: analysis_dir(workspace).join("llm_io").join("log.jsonl"),
            entries_in_file: AtomicUsize::new(usize::MAX),
        }
    }

    /// Append the entry for `event` if it is one of the LLM I/O events
    /// (`LlmRequest`, `LlmResponse`, `LlmCallFailed`); other events are
    /// ignored. A failed write is logged, never propagated — a broken log
    /// file must not take the live run down with it.
    pub fn record(&self, event: &ProgressEvent) {
        let entry = match event {
            ProgressEvent::LlmRequest {
                binary,
                function,
                attempt,
                strategy,
                prompt,
            } => Self::make_entry(
                LlmIoEntryType::Request,
                binary.as_str(),
                function,
                *attempt,
                strategy,
                prompt,
                None,
            ),
            ProgressEvent::LlmResponse {
                binary,
                function,
                attempt,
                strategy,
                content,
                tokens_used,
            } => Self::make_entry(
                LlmIoEntryType::Response,
                binary.as_str(),
                function,
                *attempt,
                strategy,
                content,
                *tokens_used,
            ),
            ProgressEvent::LlmCallFailed {
                binary,
                function,
                attempt,
                strategy,
                error,
            } => Self::make_entry(
                LlmIoEntryType::Error,
                binary.as_str(),
                function,
                *attempt,
                strategy,
                error,
                None,
            ),
            _ => return,
        };
        if let Err(e) = self.append(&entry) {
            warn!(error = %e, path = %self.path.display(), "failed to append LLM I/O log entry");
        }
    }

    /// One entry stamped now, sharing the unit metadata every LLM I/O event
    /// carries.
    fn make_entry(
        entry_type: LlmIoEntryType,
        binary: &str,
        function: &str,
        attempt: u32,
        strategy: &str,
        content: &str,
        tokens_used: Option<usize>,
    ) -> LlmIoEntry {
        LlmIoEntry {
            entry_type,
            binary: binary.to_string(),
            function: function.to_string(),
            attempt,
            strategy: strategy.to_string(),
            content: content.to_string(),
            tokens_used,
            timestamp: current_timestamp(),
        }
    }

    /// Append one entry as a JSONL line, then rotate the file back to the
    /// cap once the trim margin is exceeded.
    fn append(&self, entry: &LlmIoEntry) -> Result<(), PersistError> {
        let io = |source: std::io::Error| PersistError::Io {
            path: self.path.clone(),
            source,
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let line = serde_json::to_string(entry).map_err(|source| PersistError::Json {
            path: self.path.clone(),
            source,
        })?;
        // Count before writing: `ensure_count` reads the file, so it must
        // run while the file still holds only the previous entries.
        let count = self.ensure_count() + 1;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(io)?;
        writeln!(file, "{line}").map_err(io)?;
        self.entries_in_file.store(count, Ordering::Relaxed);
        if count > MAX_LLM_IO_ENTRIES + TRIM_MARGIN {
            self.rotate()?;
        }
        Ok(())
    }

    /// Read the retained entries in append order. A missing log reads as
    /// empty — the honest payload for a workspace that has never run live.
    /// Lines that fail to parse (a torn final line from a crash, an external
    /// edit) are skipped rather than failing the whole read.
    pub fn read(&self) -> Vec<LlmIoEntry> {
        let lines = match read_lines(&self.path) {
            Some(lines) => lines,
            None => return Vec::new(),
        };
        let mut entries = Vec::with_capacity(lines.len());
        let mut skipped = 0usize;
        for line in lines {
            match serde_json::from_str(&line) {
                Ok(entry) => entries.push(entry),
                Err(_) => skipped += 1,
            }
        }
        if skipped > 0 {
            warn!(
                skipped,
                path = %self.path.display(),
                "skipped unparseable LLM I/O log lines"
            );
        }
        entries
    }

    /// The file's current entry count, counting the file once on first use
    /// so a previous run's entries count toward the cap without paying for
    /// a read on construction.
    fn ensure_count(&self) -> usize {
        let count = self.entries_in_file.load(Ordering::Relaxed);
        if count != usize::MAX {
            return count;
        }
        read_lines(&self.path).map(|lines| lines.len()).unwrap_or(0)
    }

    /// Rewrite the file down to the newest [`MAX_LLM_IO_ENTRIES`] lines via a
    /// temp file + rename, so a reader mid-rotation still sees a complete log.
    fn rotate(&self) -> Result<(), PersistError> {
        let io = |source: std::io::Error| PersistError::Io {
            path: self.path.clone(),
            source,
        };
        let lines = read_lines(&self.path).unwrap_or_default();
        let keep = &lines[lines.len().saturating_sub(MAX_LLM_IO_ENTRIES)..];
        let seq = ROTATE_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self.path.with_extension(format!("jsonl.tmp{seq}"));
        {
            let mut file = std::fs::File::create(&tmp).map_err(io)?;
            for line in keep {
                writeln!(file, "{line}").map_err(io)?;
            }
            file.flush().map_err(io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(io)?;
        self.entries_in_file.store(keep.len(), Ordering::Relaxed);
        debug!(
            retained = keep.len(),
            path = %self.path.display(),
            "rotated LLM I/O log to its newest window"
        );
        Ok(())
    }
}

/// Read the file's non-empty lines, or `None` when it does not exist.
fn read_lines(path: &Path) -> Option<Vec<String>> {
    let content = std::fs::read_to_string(path).ok()?;
    Some(
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(String::from)
            .collect(),
    )
}

/// Unix seconds — same stamping convention as the run-telemetry logs.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use calxgloss_types::BinaryIdentity;

    fn sample_entry(n: u32) -> LlmIoEntry {
        LlmIoEntry {
            entry_type: LlmIoEntryType::Request,
            binary: "game_logic.dll".into(),
            function: format!("Fun{n}"),
            attempt: n,
            strategy: "direct".into(),
            content: format!("prompt {n}"),
            tokens_used: None,
            timestamp: 1_700_000_000 + n as u64,
        }
    }

    fn llm_request(function: &str, prompt: &str) -> ProgressEvent {
        ProgressEvent::LlmRequest {
            binary: BinaryIdentity::new("game_logic.dll"),
            function: function.into(),
            attempt: 1,
            strategy: "direct".into(),
            prompt: prompt.into(),
        }
    }

    #[test]
    fn missing_log_reads_empty() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let log = LlmIoLog::new(ws.path());
        assert!(log.read().is_empty());
        assert!(!log.path.exists());
    }

    #[test]
    fn append_then_read_round_trips_metadata_and_tokens() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let log = LlmIoLog::new(ws.path());
        let mut entry = sample_entry(1);
        entry.entry_type = LlmIoEntryType::Response;
        entry.tokens_used = Some(4321);

        log.append(&entry).expect("append succeeds");

        let back = log.read();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].entry_type, LlmIoEntryType::Response);
        assert_eq!(back[0].binary, "game_logic.dll");
        assert_eq!(back[0].function, "Fun1");
        assert_eq!(back[0].attempt, 1);
        assert_eq!(back[0].strategy, "direct");
        assert_eq!(back[0].content, "prompt 1");
        assert_eq!(back[0].tokens_used, Some(4321));
        assert_eq!(back[0].timestamp, 1_700_000_001);
    }

    #[test]
    fn record_appends_only_llm_io_events_with_their_types() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let log = LlmIoLog::new(ws.path());

        // A non-LLM event leaves nothing behind.
        log.record(&ProgressEvent::LlmCallStart {
            binary: BinaryIdentity::new("game_logic.dll"),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
        });
        log.record(&llm_request("DrawPrimitive", "the prompt"));
        log.record(&ProgressEvent::LlmResponse {
            binary: BinaryIdentity::new("game_logic.dll"),
            function: "DrawPrimitive".into(),
            attempt: 1,
            strategy: "direct".into(),
            content: "fn draw() {}".into(),
            tokens_used: Some(120),
        });
        log.record(&ProgressEvent::LlmCallFailed {
            binary: BinaryIdentity::new("game_logic.dll"),
            function: "DrawPrimitive".into(),
            attempt: 2,
            strategy: "retry".into(),
            error: "connection reset".into(),
        });

        let entries = log.read();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].entry_type, LlmIoEntryType::Request);
        assert_eq!(entries[0].content, "the prompt");
        assert_eq!(entries[1].entry_type, LlmIoEntryType::Response);
        assert_eq!(entries[1].tokens_used, Some(120));
        assert_eq!(entries[2].entry_type, LlmIoEntryType::Error);
        assert_eq!(entries[2].content, "connection reset");
        assert_eq!(entries[2].attempt, 2);
        assert_eq!(entries[2].strategy, "retry");
    }

    #[test]
    fn log_growth_is_bounded_to_the_newest_window() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let log = LlmIoLog::new(ws.path());
        let total = MAX_LLM_IO_ENTRIES + TRIM_MARGIN + 5;
        for i in 0..total {
            log.append(&sample_entry(i as u32))
                .expect("append succeeds");
        }

        let entries = log.read();
        // Bounded, not exact: rotation trims to the cap once the margin is
        // exceeded, so the retained window sits between cap and cap+margin.
        assert!(entries.len() >= MAX_LLM_IO_ENTRIES);
        assert!(entries.len() <= MAX_LLM_IO_ENTRIES + TRIM_MARGIN);
        // The newest window survives — the oldest entries were dropped.
        assert_eq!(
            entries.last().expect("window").function,
            format!("Fun{}", total - 1)
        );
        assert_ne!(entries.first().expect("window").function, "Fun0");

        // The on-disk file itself stays bounded, not just the read view.
        let on_disk = read_lines(&log.path).expect("log exists").len();
        assert!(on_disk <= MAX_LLM_IO_ENTRIES + TRIM_MARGIN);
    }

    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let ws = tempfile::tempdir().expect("temp workspace");
        let log = LlmIoLog::new(ws.path());
        log.append(&sample_entry(1)).expect("append succeeds");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log.path)
            .expect("open log")
            .write_all(b"not json at all\n")
            .expect("write junk");
        log.append(&sample_entry(2)).expect("append succeeds");

        let entries = log.read();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].function, "Fun1");
        assert_eq!(entries[1].function, "Fun2");
    }

    #[test]
    fn a_reopened_log_counts_previous_entries_toward_the_cap() {
        let ws = tempfile::tempdir().expect("temp workspace");
        LlmIoLog::new(ws.path())
            .append(&sample_entry(0))
            .expect("append succeeds");

        // Reopening (a server restart) must count what the previous run left
        // there — the cap applies across runs, not per process.
        let reopened = LlmIoLog::new(ws.path());
        assert_eq!(reopened.read().len(), 1, "previous entries survive");
        for i in 1..=MAX_LLM_IO_ENTRIES + TRIM_MARGIN {
            reopened
                .append(&sample_entry(i as u32))
                .expect("append succeeds");
        }
        // The first append re-counted the file, so rotation fired exactly
        // once the combined total passed the margin.
        let on_disk = read_lines(&reopened.path).expect("log exists").len();
        assert_eq!(on_disk, MAX_LLM_IO_ENTRIES);
    }
}
