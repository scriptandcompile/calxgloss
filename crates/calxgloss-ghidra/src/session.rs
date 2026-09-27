//! Session representation for GhidraMCP connections.

use serde::{Deserialize, Serialize};

/// A GhidraMCP analysis session.
///
/// Sessions represent an active analysis of a target binary. All queries
/// (DLL info, function disassembly, etc.) are scoped to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    pub id: String,

    /// The target binary that was loaded.
    pub target: String,

    /// Optional timestamp when the session was created.
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,

    /// Optional timestamp when the session was last active.
    #[serde(rename = "lastActiveAt")]
    pub last_active_at: Option<String>,

    /// Number of DLLs loaded in this session.
    #[serde(rename = "dllCount")]
    pub dll_count: Option<usize>,

    /// Number of functions analyzed in this session.
    #[serde(rename = "functionCount")]
    pub function_count: Option<usize>,
}

impl Session {
    /// Create a new session.
    pub fn new(id: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            target: target.into(),
            created_at: None,
            last_active_at: None,
            dll_count: None,
            function_count: None,
        }
    }

    /// Check if this session is still valid (has an ID).
    pub fn is_valid(&self) -> bool {
        !self.id.is_empty()
    }

    /// Get the session ID as a string reference.
    pub fn id_str(&self) -> &str {
        &self.id
    }

    /// Get the target binary name.
    pub fn target(&self) -> &str {
        &self.target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_new() {
        let session = Session::new("sess-1", "myapp.exe");
        assert_eq!(session.id, "sess-1");
        assert_eq!(session.target, "myapp.exe");
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_deserialize() {
        let json = r#"{
            "id": "sess-42",
            "target": "game.exe",
            "createdAt": "2025-01-01T00:00:00Z",
            "lastActiveAt": "2025-01-01T01:00:00Z",
            "dllCount": 5,
            "functionCount": 120
        }"#;

        let session: Session = serde_json::from_str(json).unwrap();
        assert_eq!(session.id, "sess-42");
        assert_eq!(session.target, "game.exe");
        assert_eq!(session.dll_count, Some(5));
        assert_eq!(session.function_count, Some(120));
    }

    #[test]
    fn test_session_serialize() {
        let session = Session::new("sess-1", "myapp.exe");
        let json = serde_json::to_string(&session).unwrap();
        assert!(json.contains("sess-1"));
        assert!(json.contains("myapp.exe"));
    }

    #[test]
    fn test_session_invalid() {
        let session = Session {
            id: String::new(),
            target: "myapp.exe".to_string(),
            created_at: None,
            last_active_at: None,
            dll_count: None,
            function_count: None,
        };
        assert!(!session.is_valid());
    }
}
