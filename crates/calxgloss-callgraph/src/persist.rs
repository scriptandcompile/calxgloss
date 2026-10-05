//! JSON persistence for call graph data.
//!
//! The [`CallGraphPersistor`] saves and loads [`CallGraph`] instances to and from
//! JSON files.

use std::path::{Path, PathBuf};

use anyhow::Result;
use calxgloss_types::persist::{JsonStore, analysis_dir};
use tracing::{info, warn};

use crate::CallGraph;

/// Saves and loads call graph data to/from JSON files.
///
/// # File Layout
///
/// Call graphs are persisted under a configurable cache directory:
///
/// ```text
/// cache_dir/
///     └── {dll_name}_call_graph.json
/// ```
///
/// The default cache directory is `{workspace_root}/re/analysis/`, but can be
/// customized via the [`CallGraphPersistor::new`] constructor or by using
/// [`CallGraphPersistor::with_cache_dir`] for an explicit path.
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
/// let persistor = CallGraphPersistor::new("/path/to/cache_dir");
/// persistor.save(&graph)?;
///
/// let loaded = persistor.load("eqmain.dll")?;
/// # Ok(())
/// # }
/// ```
pub struct CallGraphPersistor {
    store: JsonStore<CallGraph>,
}

impl CallGraphPersistor {
    /// Creates a new persistor rooted at the given workspace directory.
    ///
    /// Call graphs are stored in `<workspace_root>/re/analysis/`.
    pub fn new(workspace_root: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::with_naming(analysis_dir(workspace_root), call_graph_name),
        }
    }

    /// Creates a new persistor with an explicit cache directory.
    ///
    /// Call graphs are stored directly under the provided `cache_dir` path.
    pub fn with_cache_dir(cache_dir: impl AsRef<Path>) -> Self {
        Self {
            store: JsonStore::with_naming(cache_dir, call_graph_name),
        }
    }

    /// Returns the path where the call graph JSON file is stored.
    fn graph_path(&self, dll_name: &str) -> PathBuf {
        self.store.path_for(dll_name)
    }

    /// Saves a call graph to JSON.
    ///
    /// Creates the cache directory hierarchy if it does not exist,
    /// serializes the graph, and writes it to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if directory creation or file I/O fails.
    pub fn save(&self, graph: &CallGraph) -> Result<()> {
        info!(path = %self.graph_path(&graph.dll).display(), "Saving call graph");

        self.store.save(&graph.dll, graph)?;
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

        if !self.store.exists(dll_name) {
            warn!(path = %path.display(), "Call graph file not found");
            anyhow::bail!("Call graph not found: {}", path.display());
        }

        Ok(self.store.load(dll_name)?)
    }
}

/// Files each graph as `{dll}_call_graph.json`.
fn call_graph_name(dll_name: &str) -> String {
    format!("{dll_name}_call_graph.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CallGraphEdge, CallType, FunctionCallGraph, NodeCategory};

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

    #[test]
    fn test_save_creates_directory_hierarchy() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_mkdir");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);
        let graph = CallGraph {
            dll: "nested.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "entry".to_string(),
                address: 0x1000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Root,
            }],
        };

        persistor.save(&graph).unwrap();

        let expected_path = temp_dir.join("re").join("analysis");
        assert!(
            expected_path.exists(),
            "re/analysis/ directory should be created"
        );

        let json_path = expected_path.join("nested.dll_call_graph.json");
        assert!(json_path.exists(), "JSON file should exist");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_with_cache_dir_uses_explicit_path() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_cache_dir");
        let _ = std::fs::remove_dir_all(&temp_dir);
        let custom_cache = temp_dir.join("custom").join("cache");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::with_cache_dir(&custom_cache);
        let graph = CallGraph {
            dll: "test.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "main".to_string(),
                address: 0x401000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        };

        persistor.save(&graph).unwrap();

        let json_path = custom_cache.join("test.dll_call_graph.json");
        assert!(
            json_path.exists(),
            "JSON file should exist in custom cache directory"
        );

        let loaded = persistor.load("test.dll").unwrap();
        assert_eq!(loaded.dll, "test.dll");
        assert_eq!(loaded.functions[0].name, "main");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_load_roundtrip_preserves_addresses() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_addr");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);
        let graph = CallGraph {
            dll: "addr_test.dll".to_string(),
            functions: vec![
                FunctionCallGraph {
                    name: "caller".to_string(),
                    address: 0x180001000,
                    callers: vec![],
                    callees: vec![CallGraphEdge {
                        source: 0x180001000,
                        target: 0x180002000,
                        call_site: 0x180001010,
                        call_type: CallType::Direct,
                        callee_name: "callee".to_string(),
                    }],
                    node_category: NodeCategory::Middle,
                },
                FunctionCallGraph {
                    name: "callee".to_string(),
                    address: 0x180002000,
                    callers: vec![0x180001000],
                    callees: vec![],
                    node_category: NodeCategory::Leaf,
                },
            ],
        };

        persistor.save(&graph).unwrap();
        let loaded = persistor.load("addr_test.dll").unwrap();

        assert_eq!(loaded.functions[0].address, 0x180001000);
        assert_eq!(loaded.functions[1].address, 0x180002000);
        assert_eq!(loaded.functions[0].callees[0].call_site, 0x180001010);
        assert_eq!(loaded.functions[1].callers, vec![0x180001000]);
        assert_eq!(loaded.functions[1].node_category, NodeCategory::Leaf);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_graph_path_format() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_path");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);

        let path = persistor.graph_path("foo.dll");
        assert_eq!(
            path,
            temp_dir
                .join("re")
                .join("analysis")
                .join("foo.dll_call_graph.json")
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_graph_path_with_custom_cache_dir() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_custom_path");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let custom_cache = temp_dir.join("my").join("cache");
        let persistor = CallGraphPersistor::with_cache_dir(&custom_cache);

        let path = persistor.graph_path("foo.dll");
        assert_eq!(path, custom_cache.join("foo.dll_call_graph.json"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_multiple_graphs_independent() {
        let temp_dir = std::env::temp_dir().join("calxgloss_callgraph_test_multi");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let persistor = CallGraphPersistor::new(&temp_dir);

        let graph_a = CallGraph {
            dll: "game.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "game_loop".to_string(),
                address: 0x400000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Middle,
            }],
        };
        let graph_b = CallGraph {
            dll: "renderer.dll".to_string(),
            functions: vec![FunctionCallGraph {
                name: "render_frame".to_string(),
                address: 0x500000,
                callers: vec![],
                callees: vec![],
                node_category: NodeCategory::Leaf,
            }],
        };

        persistor.save(&graph_a).unwrap();
        persistor.save(&graph_b).unwrap();

        let loaded_a = persistor.load("game.dll").unwrap();
        let loaded_b = persistor.load("renderer.dll").unwrap();

        assert_eq!(loaded_a.dll, "game.dll");
        assert_eq!(loaded_a.functions[0].name, "game_loop");
        assert_eq!(loaded_b.dll, "renderer.dll");
        assert_eq!(loaded_b.functions[0].name, "render_frame");
        assert_ne!(loaded_a.functions[0].address, loaded_b.functions[0].address);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
