//! JSON persistence for call graph data.
//!
//! The [`CallGraphPersistor`] saves and loads [`CallGraph`] instances to and from
//! JSON files.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::{info, warn};

use crate::CallGraph;

/// Saves and loads call graph data to/from JSON files.
///
/// # File Layout
///
/// Call graphs are persisted under the `re/analysis/` directory within the
/// workspace root:
///
/// ```text
/// workspace_root/
/// └── re/
///     └── analysis/
///         └── call_graph.json
/// ```
///
/// # Example
///
/// ```no_run
/// use calxgloss_callgraph::{CallGraphPersistor, CallGraph, FunctionCallGraph, NodeCategory};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let graph = CallGraph {
///     dll: "eqmain.dll".to_string(),
///     functions: vec![FunctionCallGraph {
///         name: "main".to_string(),
///         address: 0x401000,
///         callers: vec![],
///         callees: vec![],
///         node_category: NodeCategory::Middle,
///     }],
/// };
///
/// let persistor = CallGraphPersistor::new("/path/to/workspace");
/// persistor.save(&graph)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct CallGraphPersistor {
    workspace_root: PathBuf,
}

impl CallGraphPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            workspace_root: workspace_root.as_ref().to_path_buf(),
        }
    }

    /// Returns the path where the call graph JSON file is stored.
    fn graph_path(&self, dll_name: &str) -> PathBuf {
        self.workspace_root.join("re").join("analysis").join(format!(
            "{}_call_graph.json",
            dll_name
        ))
    }

    /// Saves a call graph to JSON.
    ///
    /// Creates the `re/analysis/` directory hierarchy if it does not exist,
    /// serializes the graph, and writes it to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, graph: &CallGraph) -> Result<()> {
        let path = self.graph_path(&graph.dll);
        info!(path = %path.display(), "Saving call graph");

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(graph)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Loads a call graph from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist or fails to parse.
    pub fn load(&self, dll_name: &str) -> Result<CallGraph> {
        let path = self.graph_path(dll_name);
        info!(path = %path.display(), "Loading call graph");

        if !path.exists() {
            warn!(path = %path.display(), "Call graph file not found");
            anyhow::bail!("Call graph not found: {}", path.display());
        }

        let json = std::fs::read_to_string(&path)?;
        let graph: CallGraph = serde_json::from_str(&json)?;
        Ok(graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NodeCategory, FunctionCallGraph};

    fn sample_graph() -> CallGraph {
        CallGraph {
            dll: "test.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "main".to_string(),
                address: 0x401000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        }
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);
        let graph = sample_graph();

        persistor.save(&graph).unwrap();
        let loaded = persistor.load("test.dll").unwrap();

        assert_eq!(loaded.dll, graph.dll);
        assert_eq!(loaded.functions.len(), graph.functions.len());
        assert_eq!(loaded.functions[0].name, graph.functions[0].name);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_load_nonexistent_returns_error() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_missing");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);
        assert!(persistor.load("nonexistent.dll").is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
