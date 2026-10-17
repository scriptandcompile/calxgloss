//! `KunaSource` — the loaded program behind the scan seam's core reads (issue #206).
//!
//! Kuna's `ConsoleProgram` is full of `Rc`/`RefCell`: it is neither `Send`
//! nor `Sync`, so it can neither move to a task thread nor be shared across
//! one. `KunaSource` is therefore an actor: a dedicated engine thread owns
//! the program outright, requests arrive over an unbounded channel (whose
//! sender is `Send + Sync`, so the seam's `&self` futures stay `Send`), and
//! each answer rides a oneshot back. One handle loads exactly one target
//! binary, on that one thread — the wrong-program failure the Ghidra path
//! guards against is structurally impossible here.
//!
//! Every engine call runs inside `catch_unwind` on the engine thread: an
//! upstream panic costs one named [`KunaError::EngineFault`], never a process
//! abort. The import, export, and image-base reads answer through the
//! `object` crate from the file bytes captured beside the load itself — the
//! container tables the in-process program does not expose — so no read can
//! answer from bytes that drifted after the program loaded, and every read
//! of one source serializes against one program.
//!
//! The seam itself (`impl ScanSource for KunaSource`, and the
//! `PipelineSource::Kuna` arm) lives in `calxgloss-ghidra`, beside every
//! other `ScanSource` implementation: the trait is defined there, and a
//! kuna → ghidra dependency edge would be a cycle. This module answers in
//! Kuna-native types; the seam maps them.

use object::read::Object;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use crate::engine::{self, KunaProgram};
use crate::error::{KunaError, Result};

/// One function in the program's listing, as the Kuna engine reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaFunction {
    /// The function name as the loader named it.
    pub name: String,
    /// Entry point virtual address.
    pub address: u64,
}

/// One decompiled function, as the Kuna engine rendered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaDecompiled {
    /// The function name.
    pub name: String,
    /// The prototype line without its trailing `;`, e.g.
    /// `int fixture_tick(int count)`.
    pub signature: String,
    /// The pseudo-C body.
    pub body: String,
}

/// One import or export, as the container's tables report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaSymbol {
    /// The symbol name.
    pub name: String,
    /// The symbol's address: the export's virtual address, or `0` for an
    /// import — the container read reports the import's name and library,
    /// and no seam consumer reads an import address (the engine's own IAT
    /// slot walk can supply it when a consumer needs one).
    pub address: u64,
    /// Whether this symbol resolves outside the image.
    pub imported: bool,
}

/// What the engine thread reports back once the program is loaded and
/// scan-ready; the handle keeps these for its `Debug` and identity reads.
struct Handshake {
    identity: String,
    entry: Option<u64>,
    num_symbols: usize,
}

/// One seam read, answered on the engine thread.
enum Command {
    Functions(oneshot::Sender<Result<Vec<KunaFunction>>>),
    Decompile {
        name: String,
        reply: oneshot::Sender<Result<KunaDecompiled>>,
    },
    Imports(oneshot::Sender<Result<Vec<KunaSymbol>>>),
    Exports(oneshot::Sender<Result<Vec<KunaSymbol>>>),
    ImageBase(oneshot::Sender<Result<u64>>),
}

/// A loaded, scan-ready Kuna program behind cloneable handles.
///
/// Cloning shares the same engine thread and the same program — every
/// handle answers from the one target binary. The handle is `Send + Sync`
/// (an `Arc` around a channel sender), which is what lets the seam's
/// futures stay `Send`.
pub struct KunaSource {
    inner: Arc<SourceInner>,
}

struct SourceInner {
    tx: mpsc::UnboundedSender<Command>,
    path: PathBuf,
    identity: String,
    entry: Option<u64>,
    num_symbols: usize,
}

impl Clone for KunaSource {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl std::fmt::Debug for KunaSource {
    /// Reports the handle's identity facts — the program itself stays
    /// opaque on its engine thread.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KunaSource")
            .field("path", &self.inner.path)
            .field("identity", &self.inner.identity)
            .field("entry", &self.inner.entry)
            .field("symbols", &self.inner.num_symbols)
            .finish()
    }
}

impl KunaSource {
    /// Load `path` and hand back the source that answers from it.
    ///
    /// The load runs on the new engine thread (the program cannot be built
    /// here and moved there), so this call blocks on the handshake — call it
    /// from a plain thread, before any scan task starts, the way
    /// [`engine::load`] is called. A load failure is the same named
    /// [`KunaError::LoadFailed`] the plain loader reports, and the engine
    /// thread exits with it.
    pub fn load(path: &Path) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        // The handshake rides a plain std channel: its wait blocks the
        // calling thread wherever it is called, tokio runtime or not.
        let (handshake_tx, handshake_rx) = std::sync::mpsc::channel();
        let engine_path = path.to_path_buf();
        std::thread::spawn(move || engine_thread(engine_path, rx, handshake_tx));
        let handshake = handshake_rx
            .recv()
            .map_err(|_| KunaError::EngineUnavailable)??;
        Ok(Self {
            inner: Arc::new(SourceInner {
                tx,
                path: path.to_path_buf(),
                identity: handshake.identity,
                entry: handshake.entry,
                num_symbols: handshake.num_symbols,
            }),
        })
    }

    /// The engine's identity line for the loaded program.
    pub fn identity(&self) -> &str {
        &self.inner.identity
    }

    /// The program's entry point, when the file format names one.
    pub fn entry(&self) -> Option<u64> {
        self.inner.entry
    }

    /// The target this source answers from — the one binary the thread loaded.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Every defined function in the program, in listing order.
    pub async fn list_functions(&self) -> Result<Vec<KunaFunction>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Functions(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// The pseudo-C for one function, by name.
    pub async fn decompile_function(&self, name: &str) -> Result<KunaDecompiled> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Decompile {
            name: name.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Every import in the container's import table.
    pub async fn list_imports(&self) -> Result<Vec<KunaSymbol>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Imports(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Every export in the container's export table.
    pub async fn list_exports(&self) -> Result<Vec<KunaSymbol>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Exports(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// The base address the image is loaded at.
    pub async fn image_base(&self) -> Result<u64> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::ImageBase(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    fn send(&self, command: Command) -> Result<()> {
        self.inner
            .tx
            .send(command)
            .map_err(|_| KunaError::EngineUnavailable)
    }
}

/// The engine thread: load once, then answer commands until the last
/// handle drops and the channel closes.
fn engine_thread(
    path: PathBuf,
    mut rx: mpsc::UnboundedReceiver<Command>,
    handshake: std::sync::mpsc::Sender<Result<Handshake>>,
) {
    let mut program = match guard("load", || engine::load(&path)) {
        Ok(Ok(program)) => program,
        Ok(Err(error)) => {
            let _ = handshake.send(Err(error));
            return;
        }
        Err(fault) => {
            let _ = handshake.send(Err(fault));
            return;
        }
    };
    let info = Handshake {
        identity: program.identity().to_string(),
        entry: program.entry(),
        num_symbols: program.num_symbols(),
    };
    // The container-table reads answer from the bytes captured here, beside
    // the load itself: one file, one snapshot, so no read can ever answer
    // from bytes that drifted after the program was loaded.
    let container_bytes = match guard("container", || read_file(&path)).flatten() {
        Ok(bytes) => bytes,
        Err(fault) => {
            let _ = handshake.send(Err(fault));
            return;
        }
    };
    if handshake.send(Ok(info)).is_err() {
        return;
    }
    while let Some(command) = rx.blocking_recv() {
        match command {
            Command::Functions(reply) => {
                let _ = reply.send(guard("functions", || list_functions(&program)).flatten());
            }
            Command::Decompile { name, reply } => {
                let _ = reply.send(guard("decompile", || decompile(&mut program, &name)).flatten());
            }
            Command::Imports(reply) => {
                let _ = reply.send(
                    guard("imports", || {
                        container_symbols(&path, &container_bytes, true)
                    })
                    .flatten(),
                );
            }
            Command::Exports(reply) => {
                let _ = reply.send(
                    guard("exports", || {
                        container_symbols(&path, &container_bytes, false)
                    })
                    .flatten(),
                );
            }
            Command::ImageBase(reply) => {
                let _ = reply.send(
                    guard("image_base", || {
                        container_image_base(&path, &container_bytes)
                    })
                    .flatten(),
                );
            }
        }
    }
}

/// Run one engine call inside a panic guard: an upstream panic becomes a
/// named [`KunaError::EngineFault`], and the engine thread lives to answer
/// the next request.
fn guard<T>(call: &str, work: impl FnOnce() -> T) -> Result<T> {
    std::panic::catch_unwind(AssertUnwindSafe(work)).map_err(|payload| KunaError::EngineFault {
        call: call.to_string(),
        panic: panic_text(&payload),
    })
}

/// The panic payload as readable text — the usual `&str`/`String` payloads,
/// and a named stand-in for anything else.
fn panic_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "the engine panicked with a payload it did not print as text".to_string()
    }
}

/// The function listing, from the engine's own canonical entries.
///
/// Import entries (Kuna's synthetic addresses for call naming) are excluded:
/// the seam's `functions` listing answers with functions defined in the
/// image, and imports have their own read.
fn list_functions(program: &KunaProgram) -> Result<Vec<KunaFunction>> {
    use kuna_console::engine::EntryProvenance;
    let program = &program.program;
    Ok(program
        .function_entries_canonical()
        .into_iter()
        .filter(|entry| entry.provenance != EntryProvenance::UndefinedExternal)
        .map(|entry| KunaFunction {
            name: entry.name,
            address: program.output_address_offset(&entry.addr),
        })
        .collect())
}

/// Decompile one named function, mirroring the Kuna CLI's single-target
/// decompile: the prototype line (minus its trailing `;`) is the signature,
/// the rendered C is the body, and Kuna's per-function refusal is a named
/// failure rather than an empty answer.
fn decompile(program: &mut KunaProgram, name: &str) -> Result<KunaDecompiled> {
    use kuna_console::project::DecompileOptions;

    let program = &mut program.program;
    let Some(entry) = program.find_entry_by_name(name) else {
        return Err(KunaError::FunctionNotFound {
            name: name.to_string(),
        });
    };
    let options = DecompileOptions {
        no_vars: false,
        want_proto: true,
        want_provenance: false,
        want_callee_hints: false,
        header_carries_types: false,
        park_recovered_proto: false,
        single_target: true,
        want_tokens: false,
        want_pointer_arguments: false,
    };
    let mut results = kuna_console::project::decompile_targets_with(program, vec![entry], &options);
    let Some(result) = results.pop() else {
        return Err(KunaError::DecompileFailed {
            name: name.to_string(),
            reason: "the engine answered the one-target batch with no result".to_string(),
        });
    };
    let Some(body) = result.code else {
        return Err(KunaError::DecompileFailed {
            name: name.to_string(),
            reason: result
                .error
                .unwrap_or_else(|| "the engine produced no output".to_string()),
        });
    };
    let signature = result
        .proto
        .map(|proto| proto.trim().trim_end_matches(';').trim_end().to_string())
        .unwrap_or_default();
    Ok(KunaDecompiled {
        name: result.name,
        signature,
        body,
    })
}

/// Parse the same file the engine loaded, for the container-table reads.
fn parse_container<'data>(data: &'data [u8], path: &Path) -> Result<object::read::File<'data>> {
    object::read::File::parse(data).map_err(|error| KunaError::TablesUnreadable {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

/// The import or export listing, from the container's tables in the
/// bytes captured at load time.
fn container_symbols(path: &Path, data: &[u8], imported: bool) -> Result<Vec<KunaSymbol>> {
    let file = parse_container(data, path)?;
    let symbols = if imported {
        file.imports()
            .map_err(table_error(path))?
            .into_iter()
            .map(|import| KunaSymbol {
                name: name_text(import.name()),
                address: 0,
                imported: true,
            })
            .collect()
    } else {
        file.exports()
            .map_err(table_error(path))?
            .into_iter()
            .map(|export| KunaSymbol {
                name: name_text(export.name()),
                address: export.address(),
                imported: false,
            })
            .collect()
    };
    Ok(symbols)
}

/// The image base, from the PE optional header in the bytes captured at
/// load time.
///
/// PE is the only container reported today: it is the container the pinned
/// engine's x86 specs actually scan, and the other formats' bases (ELF's
/// first `PT_LOAD`, Mach-O's first non-zero segment) arrive with their
/// languages. A non-PE target fails by name rather than answering a guess.
fn container_image_base(path: &Path, data: &[u8]) -> Result<u64> {
    use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
    let file = parse_container(data, path)?;
    match &file {
        object::read::File::Pe32(pe) => Ok(pe.nt_headers().optional_header().image_base()),
        object::read::File::Pe64(pe) => Ok(pe.nt_headers().optional_header().image_base()),
        other => Err(KunaError::TablesUnreadable {
            path: path.display().to_string(),
            reason: format!(
                "the Kuna source reports the image base for PE containers only; this file is {:?}",
                other.format(),
            ),
        }),
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| KunaError::TablesUnreadable {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

fn table_error(path: &Path) -> impl FnOnce(object::read::Error) -> KunaError + use<'_> {
    move |error| KunaError::TablesUnreadable {
        path: path.display().to_string(),
        reason: error.to_string(),
    }
}

/// A container symbol name as text; the tables hold bytes, and a name that
/// is not UTF-8 keeps its readable prefix rather than being dropped.
fn name_text(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_call_becomes_an_engine_fault_not_an_abort() {
        let fault = guard("boom", || panic!("engine exploded internally"))
            .expect_err("the panic must arrive as an error");
        match &fault {
            KunaError::EngineFault { call, panic } => {
                assert_eq!(call, "boom");
                assert!(
                    panic.contains("engine exploded"),
                    "the payload should survive: {panic}"
                );
            }
            other => panic!("expected an EngineFault, got {other:?}"),
        }
        // The message names the fallback, like every other Kuna failure.
        assert!(fault.to_string().contains("--engine ghidra"));
    }

    #[test]
    fn a_non_text_panic_payload_still_names_the_call() {
        let fault = guard("weird", || std::panic::panic_any(42u32))
            .expect_err("a payload-less panic is still a fault");
        assert!(
            matches!(&fault, KunaError::EngineFault { call, .. } if call == "weird"),
            "expected an EngineFault naming the call, got {fault:?}"
        );
    }
}
