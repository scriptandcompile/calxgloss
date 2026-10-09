//! Binary identity, unit key, and the branch-name grammar that carries both.
//!
//! A *binary identity* is a target binary's filename verbatim, extension
//! included (`game_logic.dll`, `eqgame.exe`) — the same string names
//! translation branches (`re/{file}/{function}v{N}`), unit keys
//! (`{file}/{function}`), artifact directories, and UI display (issue #68).
//! A *unit key* is `{file}/{function}`. This module owns those concepts as
//! small types, plus the one parser of the branch-name grammar: every crate
//! that reads a branch name or a unit reference goes through
//! [`parse_branch_name`] rather than restating the format.

use std::fmt::{self, Display};
use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::dashboard::WorkKind;

/// A target binary's filename verbatim, extension included — the binary's
/// identity (issue #68).
///
/// The identity is never normalized: no case folding, no extension
/// stripping. `foo.dll` and `foo.exe` are different binaries. Deriving Rust
/// identifiers (crate and shim file names) from a binary name takes the
/// stem — that is naming, not identity, and stays a plain string.
///
/// Serializes as the bare filename (`#[serde(transparent)]`), so JSON
/// payloads carry the identity exactly as they did before the type existed.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BinaryIdentity(String);

impl BinaryIdentity {
    /// Wraps a filename verbatim as a binary identity.
    pub fn new(name: impl Into<String>) -> Self {
        BinaryIdentity(name.into())
    }

    /// The identity string, verbatim.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for BinaryIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for BinaryIdentity {
    fn from(s: &str) -> Self {
        BinaryIdentity(s.to_string())
    }
}

impl From<String> for BinaryIdentity {
    fn from(s: String) -> Self {
        BinaryIdentity(s)
    }
}

impl From<&String> for BinaryIdentity {
    fn from(s: &String) -> Self {
        BinaryIdentity(s.clone())
    }
}

impl From<&BinaryIdentity> for BinaryIdentity {
    fn from(s: &BinaryIdentity) -> Self {
        s.clone()
    }
}

impl AsRef<str> for BinaryIdentity {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<std::path::Path> for BinaryIdentity {
    fn as_ref(&self) -> &std::path::Path {
        std::path::Path::new(&self.0)
    }
}

impl Deref for BinaryIdentity {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for BinaryIdentity {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for BinaryIdentity {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for BinaryIdentity {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

/// A unit's identity string: `{binary}/{function}` (glossary: *unit key*).
///
/// Carried verbatim through API payloads, review records, and artifact
/// paths. Function names never contain `/`, so the two parts always split
/// back apart on the first slash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitKey {
    binary: BinaryIdentity,
    function: String,
}

impl UnitKey {
    /// Builds the unit key for a binary identity and function name.
    pub fn new(binary: &BinaryIdentity, function: impl Into<String>) -> Self {
        UnitKey {
            binary: binary.clone(),
            function: function.into(),
        }
    }

    /// The binary part of the key.
    pub fn binary(&self) -> &BinaryIdentity {
        &self.binary
    }

    /// The function part of the key.
    pub fn function(&self) -> &str {
        &self.function
    }
}

impl Display for UnitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.binary, self.function)
    }
}

/// The parsed components of a translation branch name or unit reference.
///
/// Produced by [`parse_branch_name`], the one owner of the
/// `re/{file}/{function}v{N}` grammar (issue #69).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchName {
    /// What kind of work the branch carries — function translation or one
    /// of the supporting kinds named by its first path segment.
    pub kind: WorkKind,
    /// The branch's first path segment. For function-translation branches
    /// this is the binary identity; for supporting-work branches it is the
    /// work-kind prefix (`classify`, `shim`, …) and the subject of the work
    /// sits in [`function`](BranchName::function) — the convention the
    /// dashboard keys units by.
    pub binary: BinaryIdentity,
    /// The function (or supporting-work subject) after the first segment,
    /// `None` when the name has only one segment.
    pub function: Option<String>,
    /// The attempt number, `None` when the name carries no `v{N}` suffix.
    /// Callers that treat a missing attempt as the first one use
    /// `attempt.unwrap_or(1)`.
    pub attempt: Option<u32>,
}

/// Parses a translation branch name or unit reference into its components.
///
/// The grammar is `re/{file}/{function}v{N}`: an optional `re/` prefix, the
/// first path segment (a binary identity, or a supporting-work prefix from
/// [`work_kind_for_prefix`]), an optional second segment, and an optional
/// attempt suffix — glued to the function (`DrawSpritev1`) or as its own
/// segment (`/v3`, the unit-reference form used by `dashboard view`).
/// Returns `None` only when there is no first segment to name.
///
/// # Examples
///
/// ```
/// use calxgloss_types::{WorkKind, parse_branch_name};
///
/// let parts = parse_branch_name("re/game_logic.dll/DrawSpritev2").unwrap();
/// assert_eq!(parts.kind, WorkKind::FunctionTranslation);
/// assert_eq!(parts.binary.as_str(), "game_logic.dll");
/// assert_eq!(parts.function.as_deref(), Some("DrawSprite"));
/// assert_eq!(parts.attempt, Some(2));
/// ```
pub fn parse_branch_name(name: &str) -> Option<BranchName> {
    let rest = name.strip_prefix("re/").unwrap_or(name);

    // Attempt suffix: a trailing `v{N}`. It is either glued to the function
    // (`DrawSpritev1`) or a whole segment (`/v3`); a `v` followed by
    // anything but digits is part of a name.
    let (rest, attempt) = match rest.rfind('v') {
        Some(pos) => {
            let after = &rest[pos + 1..];
            match after.parse::<u32>() {
                Ok(attempt) if !after.is_empty() && after.bytes().all(|b| b.is_ascii_digit()) => {
                    (&rest[..pos], Some(attempt))
                }
                _ => (rest, None),
            }
        }
        None => (rest, None),
    };
    // A separate `/v{N}` segment leaves a trailing slash behind.
    let rest = rest.strip_suffix('/').unwrap_or(rest);

    let mut segments = rest.splitn(2, '/');
    let first = segments.next().filter(|s| !s.is_empty())?;
    let function = segments.next().map(str::to_string);

    Some(BranchName {
        kind: work_kind_for_prefix(first).unwrap_or(WorkKind::FunctionTranslation),
        binary: BinaryIdentity::new(first),
        function,
        attempt,
    })
}

/// Maps a branch name's first path segment to its supporting work kind
/// (`shim`, `pal`, …); any other segment is a binary name, making the
/// branch a function translation.
pub fn work_kind_for_prefix(prefix: &str) -> Option<WorkKind> {
    match prefix {
        "classify" => Some(WorkKind::DllClassification),
        "shim" => Some(WorkKind::ShimLayer),
        "pal" => Some(WorkKind::PalTrait),
        "test" => Some(WorkKind::TestCaseAddition),
        "integration" => Some(WorkKind::IntegrationStep),
        "fix" => Some(WorkKind::BugFix),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_identity_stays_verbatim() {
        let identity = BinaryIdentity::new("LaunchPad.exe");
        assert_eq!(identity.as_str(), "LaunchPad.exe");
        assert_eq!(identity.to_string(), "LaunchPad.exe");
        assert_eq!(identity, "LaunchPad.exe");
        assert_ne!(identity, BinaryIdentity::new("LaunchPad"));
    }

    #[test]
    fn binary_identity_serializes_as_bare_filename() {
        let identity = BinaryIdentity::new("game_logic.dll");
        let json = serde_json::to_string(&identity).unwrap();
        assert_eq!(json, "\"game_logic.dll\"");
        let back: BinaryIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, identity);
    }

    #[test]
    fn unit_key_formats_and_splits() {
        let binary = BinaryIdentity::new("game_logic.dll");
        let key = UnitKey::new(&binary, "DrawSprite");
        assert_eq!(key.to_string(), "game_logic.dll/DrawSprite");
        assert_eq!(key.binary(), &binary);
        assert_eq!(key.function(), "DrawSprite");
    }

    #[test]
    fn parse_reads_canonical_branch_name() {
        let parts = parse_branch_name("re/game_logic.dll/DrawSpritev1").unwrap();
        assert_eq!(parts.kind, WorkKind::FunctionTranslation);
        assert_eq!(parts.binary, BinaryIdentity::new("game_logic.dll"));
        assert_eq!(parts.function.as_deref(), Some("DrawSprite"));
        assert_eq!(parts.attempt, Some(1));
    }

    #[test]
    fn parse_keeps_attempt_absent_when_suffix_missing() {
        let parts = parse_branch_name("re/game_logic.dll/DrawSprite").unwrap();
        assert_eq!(parts.attempt, None);
        assert_eq!(parts.function.as_deref(), Some("DrawSprite"));
    }

    #[test]
    fn parse_reads_supporting_branches() {
        let classify = parse_branch_name("re/classify/game_logic.dllv1").unwrap();
        assert_eq!(classify.kind, WorkKind::DllClassification);
        assert_eq!(classify.binary.as_str(), "classify");
        assert_eq!(classify.function.as_deref(), Some("game_logic.dll"));
        assert_eq!(classify.attempt, Some(1));

        let shim = parse_branch_name("re/shim/wgpu").unwrap();
        assert_eq!(shim.kind, WorkKind::ShimLayer);
        assert_eq!(shim.function.as_deref(), Some("wgpu"));
    }

    #[test]
    fn parse_reads_unit_reference_with_separate_attempt_segment() {
        let parts = parse_branch_name("game_logic.dll/DrawPrimitive/v3").unwrap();
        assert_eq!(parts.binary, BinaryIdentity::new("game_logic.dll"));
        assert_eq!(parts.function.as_deref(), Some("DrawPrimitive"));
        assert_eq!(parts.attempt, Some(3));
    }

    #[test]
    fn parse_keeps_v_inside_names_as_name() {
        let parts = parse_branch_name("re/game_logic.dll/DrawVertex").unwrap();
        assert_eq!(parts.function.as_deref(), Some("DrawVertex"));
        assert_eq!(parts.attempt, None);

        let parts = parse_branch_name("re/game_logic.dll/DrawVertexv2").unwrap();
        assert_eq!(parts.function.as_deref(), Some("DrawVertex"));
        assert_eq!(parts.attempt, Some(2));
    }

    #[test]
    fn parse_rejects_names_without_a_first_segment() {
        assert!(parse_branch_name("").is_none());
        assert!(parse_branch_name("re/").is_none());
    }

    #[test]
    fn parse_round_trips_git_branch_names() {
        let branch = crate::GitBranch::new("game_logic.dll", "DrawSprite", 2).unwrap();
        let parts = parse_branch_name(&branch.name).unwrap();
        assert_eq!(parts.binary, branch.binary);
        assert_eq!(parts.function.as_deref(), Some(branch.function.as_str()));
        assert_eq!(parts.attempt, Some(branch.attempt));
    }
}
