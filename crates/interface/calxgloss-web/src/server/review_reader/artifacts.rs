//! The artifact seam: the reader's walks of the pipeline artifacts behind
//! the binary pages (issue #464) — the shim tracker's documents under
//! `re/shims/` and the per-function analysis artifacts under
//! `re/analysis/`. Every walk follows one rule: the binary directory is
//! matched case-insensitively like every other review comparison, and
//! when several spellings match, the alphabetically first wins. A
//! missing file is an honest absence. A corrupt document is no
//! document, never a zeroed one.

use super::*;

use calxgloss_types::{SHIM_MAPPINGS_FILE, SHIM_SOURCE_FILE, SHIM_VERIFICATION_FILE};

impl ReviewSurfaceReader {
    /// The shim tracker's artifact reading for one binary (issue #464):
    /// the API mappings and the verification result the shim pipeline
    /// files under `re/shims/{binary}/`. Each document stands or falls
    /// on its own — a corrupt artifact is no artifact, and it never
    /// takes the readable document beside it down with it.
    pub(crate) fn shim_readout(&self, name: &str) -> ShimReadout {
        let dir = self.binary_artifact_dir(&calxgloss_types::shim_artifacts_dir(&self.repo_path), name);
        ShimReadout {
            mappings: dir.as_deref().and_then(|dir| read_artifact(dir, SHIM_MAPPINGS_FILE)),
            verification: dir
                .as_deref()
                .and_then(|dir| read_artifact(dir, SHIM_VERIFICATION_FILE)),
        }
    }

    /// The API-call categories the binary's persisted per-function
    /// analysis artifacts actually record — the honest input to the
    /// PAL-trait derivation. A missing or unreadable directory is no
    /// categories; a corrupt artifact contributes nothing while the
    /// readable ones still answer. Sorted and deduplicated verbatim.
    pub(crate) fn api_call_categories(&self, name: &str) -> Vec<String> {
        let Some(dir) = self.binary_artifact_dir(
            &calxgloss_types::analysis_dir(&self.repo_path),
            name,
        ) else {
            return Vec::new();
        };
        let mut categories: Vec<String> = std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "json"))
            .filter_map(|path| read_json_at::<FunctionArtifactReading>(&path))
            .filter_map(|artifact| artifact.windows_apis)
            .flatten()
            .map(|api| api.category)
            .filter(|category| !category.is_empty())
            .collect();
        categories.sort();
        categories.dedup();
        categories
    }

    /// The workspace's generated PAL/shim source texts — the honest
    /// input for trait existence, reading no new persistence format:
    /// every `.rs` under `scratch/pal/src/` plus every binary's
    /// generated `re/shims/{binary}/shim.rs` ([`SHIM_SOURCE_FILE`]; test
    /// sources reference traits without defining them). Unreadable
    /// files are skipped; no sources is the honest empty answer.
    pub(crate) fn pal_source_texts(&self) -> Vec<String> {
        let mut pal_files: Vec<PathBuf> =
            std::fs::read_dir(self.repo_path.join("scratch").join("pal").join("src"))
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
                .collect();
        pal_files.sort();

        let mut shim_files: Vec<PathBuf> =
            std::fs::read_dir(calxgloss_types::shim_artifacts_dir(&self.repo_path))
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.is_dir())
                .map(|dir| dir.join(SHIM_SOURCE_FILE))
                .filter(|path| path.is_file())
                .collect();
        shim_files.sort();

        pal_files
            .into_iter()
            .chain(shim_files)
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .collect()
    }

    /// One unit's analysis artifact (`re/analysis/{binary}/{function}.json`)
    /// read once for every review surface that consumes it — the
    /// API-mapping section, the tier rationale, and the decomp panel each
    /// used to parse the same document through their own private shape
    /// (issue #464). Absent, unreadable, or corrupt is an honest `None`;
    /// each surface states its own degrade policy at the read site.
    pub(crate) fn function_artifact(
        &self,
        binary: &str,
        function: &str,
    ) -> Option<FunctionArtifactReading> {
        if function.is_empty() {
            return None;
        }
        read_json_at(&calxgloss_types::analysis_artifact_path(
            &self.repo_path,
            binary,
            function,
        ))
    }

    /// The per-binary call-graph record (`re/analysis/{binary}_call_graph.json`)
    /// read whole. A never-filed or corrupt record is an empty graph — the
    /// honest no-context answer the unit detail renders as empty sections.
    pub(crate) fn call_graph_record(&self, binary: &str) -> CallGraphReading {
        read_json_at(&calxgloss_types::call_graph_record_path(&self.repo_path, binary))
            .unwrap_or_default()
    }

    /// The per-binary artifact directory under `root` whose directory
    /// name is the binary's — the one walk the shim and PAL reads share.
    /// Matched case-insensitively like every other server binary join;
    /// when several spellings match, the alphabetically first wins. No
    /// matching directory is the honest "no artifacts" answer.
    fn binary_artifact_dir(&self, root: &Path, name: &str) -> Option<PathBuf> {
        let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|dir_name| binary_matches(dir_name, name))
            })
            .collect();
        dirs.sort();
        dirs.into_iter().next()
    }
}

/// What one binary's shim artifact directory declares: each filed
/// document as its own reading, `None` for the missing or the corrupt.
#[derive(Debug, Default)]
pub(crate) struct ShimReadout {
    pub mappings: Option<calxgloss_types::ShimLayer>,
    pub verification: Option<calxgloss_types::ShimVerificationResult>,
}

/// Reads one artifact document, honestly `None` when the file is
/// missing or corrupt — a corrupt artifact is no artifact, never a
/// zeroed one.
fn read_artifact<T: serde::de::DeserializeOwned>(dir: &Path, file: &str) -> Option<T> {
    read_json_at(&dir.join(file))
}

/// Reads one JSON document from a path, `None` on any fault.
fn read_json_at<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
}

/// The subset of the pipeline's per-function analysis artifact
/// (`re/analysis/{binary}/{function}.json`) the review surfaces read:
/// the tagged Windows API calls with their categories and PAL mappings,
/// the recorded disassembly and decompiler output, and the artifact's
/// own function-name stamp. Every field defaults when absent — the
/// artifact format stays the pipeline's, this reader renders.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct FunctionArtifactReading {
    /// Absent means never filed; an empty list means filed and empty —
    /// the distinction the decomp payload carries verbatim.
    #[serde(default)]
    pub windows_apis: Option<Vec<ApiCallReading>>,
    #[serde(default)]
    pub disassembly: String,
    #[serde(default)]
    pub function_name: Option<String>,
    #[serde(default)]
    pub decompiler_output: Option<String>,
}

/// One tagged Windows API call as the analysis artifact records it.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ApiCallReading {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub pal_mapping: String,
}

/// The subset of the per-binary call-graph record the unit detail's
/// caller/callee context reads. The record format stays the analysis
/// scan's; the web resolves addresses to names at the read site.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct CallGraphReading {
    #[serde(default)]
    pub functions: Vec<CallGraphFunctionReading>,
}

/// One function node as the call-graph record files it.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct CallGraphFunctionReading {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub address: u64,
    #[serde(default)]
    pub callers: Vec<u64>,
    #[serde(default)]
    pub callees: Vec<CallGraphEdgeReading>,
}

/// One callee edge as the call-graph record files it.
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct CallGraphEdgeReading {
    #[serde(default)]
    pub target: u64,
    #[serde(default)]
    pub callee_name: String,
}
