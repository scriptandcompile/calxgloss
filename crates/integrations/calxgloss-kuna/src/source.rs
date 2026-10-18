//! `KunaSource` — the loaded program behind every scan seam read (issues
//! #206 and #207).
//!
//! Kuna's `ConsoleProgram` is full of `Rc`/`RefCell`: it is neither `Send`
//! nor `Sync`, so it can neither move to a task thread nor be shared across
//! one. `KunaSource` is therefore an actor: a dedicated engine thread owns
//! the program outright, requests arrive over an unbounded channel (whose
//! sender is `Send + Sync`, so the seam's `&self` futures stay `Send`), and
//! each answer rides a oneshot back. One handle loads exactly one target
//! binary, on that one thread — a wrong-program mix-up is structurally
//! impossible here.
//!
//! Every engine call runs inside `catch_unwind` on the engine thread: an
//! upstream panic costs one named [`KunaError::EngineFault`], never a process
//! abort. The import, export, and image-base reads answer through the
//! `object` crate from the file bytes captured beside the load itself — the
//! container tables the in-process program does not expose — so no read can
//! answer from bytes that drifted after the program loaded, and every read
//! of one source serializes against one program. The string inventory and
//! the xref walk read the same snapshot through the engine's own analysis
//! tier; the type-library, struct-layout, enum-values, data-item, and
//! memory reads answer from the program itself (issue #207). The xref index
//! is built once, lazily, on the first xref-shaped read and cached on the
//! thread, so every later read pays only the query.
//!
//! The seam itself (`impl ScanSource for KunaSource`, and the
//! `PipelineSource::Kuna` arm) lives in `calxgloss-decomp`, beside every
//! other `ScanSource` implementation: the trait is defined there, and a
//! kuna → decomp dependency edge would be a cycle. This module answers in
//! Kuna-native types; the seam maps them.
//!
//! The write-back plane (issue #209): Kuna never writes back into the
//! image, so a type write compiles to a directive in the
//! [`DirectivePlane`] the engine thread owns, persists to the record of
//! effort, and replays through the engine's assertion plane on every load.
//! A program-scoped write is applied live and reported by the engine's own
//! per-directive outcome; a local-type write is installed for the decompile
//! loop to apply; a struct-field addition regenerates the owning record,
//! which takes effect on the next load — Kuna refuses to re-body a
//! completed record.
//!
//! The pass heartbeat and the decompile budgets (issue #211): a scan pass
//! arms the source with [`begin_pass`](KunaSource::begin_pass), and while
//! armed every completed decompile beats a throttled
//! [`ProgressEvent::BatchProgress`] in a shape the web UI and logs already
//! render, so progress semantics are identical whichever scan runs. Per-function instruction/time/memory budgets
//! ([`KunaBudget`]) are armed at load; a function that trips one fails with
//! the named [`KunaError::DecompileBudgetExceeded`] instead of hanging or
//! exhausting the box.

use object::read::Object;
use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use calxgloss_types::{BinaryIdentity, ProgressEvent, TranslationEvents};
use tokio::sync::{mpsc, oneshot};

use crate::budget::KunaBudget;
use crate::directives::{self, DirectiveOutcome, DirectivePlane, KunaNewField};
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

/// One string literal, as the engine's own string inventory found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaString {
    /// VMA of the first character byte.
    pub address: u64,
    /// The decoded text, terminator excluded.
    pub value: String,
}

/// One reference into an address, as the engine's xref walk indexed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaXref {
    /// VMA of the referencing instruction.
    pub address: u64,
    /// The function holding the reference, when the walk owned the site by
    /// a function the listing names.
    pub function: Option<String>,
    /// The engine's own kind word: `call`, `jump`, `data`, `read`, `write`.
    pub kind: Option<String>,
}

/// A named type in the engine's interned type factory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaDataType {
    /// The type name.
    pub name: String,
    /// The kind-derived category the listing synthesizes: `struct`, `union`,
    /// `enum`, `typedef`, `pointer`, `array`, `builtin`, or `other`.
    pub category: String,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Synthetic manager path, `/{category}/{name}`.
    pub path: String,
}

/// One field of a structure's layout, bitfield-bearing rows included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaStructField {
    /// Byte offset of the field from the start of the structure.
    pub offset: u64,
    /// Size in bytes; a bitfield row reports its container's byte size.
    pub size: u64,
    /// The field's type name.
    pub type_name: String,
    /// Field name.
    pub field_name: String,
}

/// A structure's full field layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaStructLayout {
    /// The structure name.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub alignment: u64,
    /// Defined fields, in offset order.
    pub fields: Vec<KunaStructField>,
}

/// One member of an enumeration, valued as the engine's own C rendering
/// spells it (signed enums carry negative members).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaEnumMember {
    /// Member name.
    pub name: String,
    /// Member value, sign-extended for signed enums.
    pub value: i64,
}

/// An enumeration and its members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaEnumDefinition {
    /// The enumeration name.
    pub name: String,
    /// Storage size in bytes.
    pub size: u64,
    /// The members, in the engine's value order.
    pub members: Vec<KunaEnumMember>,
}

/// A labeled, typed global in the engine's symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KunaDataItem {
    /// The symbol's label.
    pub label: String,
    /// VMA of the object.
    pub address: u64,
    /// The applied type's name.
    pub type_name: String,
    /// Size in bytes.
    pub length: u64,
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
    Strings(oneshot::Sender<Result<Vec<KunaString>>>),
    XrefsTo {
        address: u64,
        reply: oneshot::Sender<Result<Vec<KunaXref>>>,
    },
    DataTypes {
        category: Option<String>,
        reply: oneshot::Sender<Result<Vec<KunaDataType>>>,
    },
    StructLayout {
        name: String,
        reply: oneshot::Sender<Result<KunaStructLayout>>,
    },
    EnumValues {
        name: String,
        reply: oneshot::Sender<Result<KunaEnumDefinition>>,
    },
    DataItems(oneshot::Sender<Result<Vec<KunaDataItem>>>),
    ReadMemory {
        address: u64,
        length: usize,
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    SetPrototype {
        address: u64,
        prototype: String,
        reply: oneshot::Sender<Result<()>>,
    },
    SetLocalType {
        address: u64,
        variable: String,
        type_name: String,
        reply: oneshot::Sender<Result<()>>,
    },
    CreateStruct {
        name: String,
        fields: Vec<(String, String)>,
        reply: oneshot::Sender<Result<()>>,
    },
    CreateEnum {
        name: String,
        values: Vec<(String, i64)>,
        size: u32,
        reply: oneshot::Sender<Result<()>>,
    },
    CreateTypedef {
        name: String,
        base_type: String,
        reply: oneshot::Sender<Result<()>>,
    },
    AddStructField {
        struct_name: String,
        field_name: String,
        field_type: String,
        offset: Option<u32>,
        reply: oneshot::Sender<Result<()>>,
    },
    DirectiveFates(oneshot::Sender<Result<Vec<DirectiveOutcome>>>),
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
    directive_file: Option<PathBuf>,
    identity: String,
    entry: Option<u64>,
    num_symbols: usize,
    /// Armed by `begin_pass` while an analysis pass walks the program;
    /// clones share it so every handle to one source beats as one
    /// (issue #211).
    heartbeat: Mutex<Option<Arc<Heartbeat>>>,
}

/// Minimum gap between heartbeat beats for one pass — a 20k-function scan
/// must not flood the event channel.
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);

/// Shared state for one analysis pass's progress heartbeat.
///
/// A pass (`begin_pass`) arms the source: while armed, every completed
/// decompile counts as one work item and beats a `BatchProgress` event,
/// throttled to [`HEARTBEAT_INTERVAL`]. `list_functions` during the pass
/// records the work list — its size is the total. Kuna decompiles by name,
/// so the beat names the function the caller asked for directly —
/// no address-to-name resolution is needed.
#[derive(Debug)]
struct Heartbeat {
    binary: BinaryIdentity,
    pass: String,
    events: TranslationEvents,
    total: AtomicUsize,
    index: AtomicUsize,
    last_beat: Mutex<Option<Instant>>,
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
            .field("directive_file", &self.inner.directive_file)
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
        Self::load_with_directives(path, None)
    }

    /// Load `path` with its write-back directive plane at `directive_file`.
    ///
    /// The plane file is Kuna's own `--assert` line syntax (see
    /// [`crate::directives`]): a missing file is an empty plane that the
    /// first write creates, and an existing file replays through the
    /// engine's assertion plane before the handshake — directives the
    /// engine refuses are not fatal to the load, and [`directive_fates`](Self::directive_fates)
    /// reports them by name. A file the directive grammar cannot parse is a
    /// named [`KunaError::DirectiveFileInvalid`] load failure: a
    /// half-understood plane must never replay as a quiet partial.
    /// `None` gives an in-memory plane that persists nowhere.
    pub fn load_with_directives(path: &Path, directive_file: Option<&Path>) -> Result<Self> {
        Self::load_with_budget(path, directive_file, KunaBudget::default())
    }

    /// Load `path` with its directive plane and its per-function decompile
    /// budgets armed (issue #211).
    ///
    /// The budgets are armed on the engine thread before the handshake, so
    /// the first decompile the caller sees is already bounded; an unset
    /// knob leaves Kuna's own default in force. A memory limit on a
    /// platform that cannot read the process's resident set is refused by
    /// name before anything spawns — [`KunaError::BudgetUnsupported`] —
    /// because a watchdog that can never fire is a silent no-op.
    pub fn load_with_budget(
        path: &Path,
        directive_file: Option<&Path>,
        budget: KunaBudget,
    ) -> Result<Self> {
        budget.validate()?;
        let (tx, rx) = mpsc::unbounded_channel();
        // The handshake rides a plain std channel: its wait blocks the
        // calling thread wherever it is called, tokio runtime or not.
        let (handshake_tx, handshake_rx) = std::sync::mpsc::channel();
        let engine_path = path.to_path_buf();
        let plane_file = directive_file.map(Path::to_path_buf);
        let plane_for_inner = plane_file.clone();
        std::thread::spawn(move || {
            engine_thread(engine_path, plane_file, budget, rx, handshake_tx)
        });
        let handshake = handshake_rx
            .recv()
            .map_err(|_| KunaError::EngineUnavailable)??;
        Ok(Self {
            inner: Arc::new(SourceInner {
                tx,
                path: path.to_path_buf(),
                directive_file: plane_for_inner,
                identity: handshake.identity,
                entry: handshake.entry,
                num_symbols: handshake.num_symbols,
                heartbeat: Mutex::new(None),
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

    // =========================================================
    // Analysis-pass heartbeat (issue #211)
    // =========================================================

    /// Arm the heartbeat for one analysis pass over the loaded program.
    ///
    /// While armed, every completed decompile beats a
    /// [`ProgressEvent::BatchProgress`] naming the pass and the function it
    /// just pulled, in a shape the web UI and logs
    /// already render — progress semantics are identical whichever scan
    /// runs.
    /// One pass at a time: a new `begin_pass` replaces any pass left armed
    /// by an error path that skipped [`end_pass`](Self::end_pass).
    pub fn begin_pass(&self, binary: &str, pass: &str, events: &TranslationEvents) {
        *self.inner.heartbeat.lock().expect("heartbeat lock") = Some(Arc::new(Heartbeat {
            binary: binary.into(),
            pass: pass.to_string(),
            events: events.clone(),
            total: AtomicUsize::new(0),
            index: AtomicUsize::new(0),
            last_beat: Mutex::new(None),
        }));
    }

    /// Disarm the heartbeat — the pass is done, later reads are ordinary.
    pub fn end_pass(&self) {
        *self.inner.heartbeat.lock().expect("heartbeat lock") = None;
    }

    /// Record the pass's work list: its size is the total the beats count
    /// against. `list_functions` notes it automatically during an armed
    /// pass; the read cache also notes the listing it served warm, so a
    /// cached run's "n of m" keeps moving (issue #121).
    pub fn note_worklist(&self, total: usize) {
        if let Some(hb) = self.active_heartbeat() {
            hb.total.store(total, Ordering::Relaxed);
        }
    }

    /// Count one completed decompile and beat if due: always for the first
    /// and last item, otherwise at most once per [`HEARTBEAT_INTERVAL`].
    ///
    /// `decompile_function` ticks itself; the read cache calls this for a
    /// body served warm, which never reaches the engine but is still a work
    /// item the pass consumed (issue #121).
    pub fn tick(&self, name: &str) {
        let Some(hb) = self.active_heartbeat() else {
            return;
        };
        let index = hb.index.fetch_add(1, Ordering::Relaxed) + 1;
        let total = hb.total.load(Ordering::Relaxed);
        let now = Instant::now();
        let due = index == 1
            || (total > 0 && index == total)
            || hb
                .last_beat
                .lock()
                .expect("last_beat lock")
                .map(|t| now.duration_since(t) >= HEARTBEAT_INTERVAL)
                .unwrap_or(true);
        if !due {
            return;
        }
        *hb.last_beat.lock().expect("last_beat lock") = Some(now);
        hb.events.emit(ProgressEvent::BatchProgress {
            binary: hb.binary.clone(),
            pass: hb.pass.clone(),
            function: name.to_string(),
            index,
            total,
        });
    }

    fn active_heartbeat(&self) -> Option<Arc<Heartbeat>> {
        self.inner.heartbeat.lock().expect("heartbeat lock").clone()
    }

    /// Every defined function in the program, in listing order.
    pub async fn list_functions(&self) -> Result<Vec<KunaFunction>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Functions(reply))?;
        let list = answer.await.map_err(|_| KunaError::EngineUnavailable)??;
        self.note_worklist(list.len());
        Ok(list)
    }

    /// The pseudo-C for one function, by name.
    pub async fn decompile_function(&self, name: &str) -> Result<KunaDecompiled> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Decompile {
            name: name.to_string(),
            reply,
        })?;
        let outcome = answer.await.map_err(|_| KunaError::EngineUnavailable)?;
        // The round trip completed — one work item of any armed pass done,
        // whether or not the engine answered with a body: a function that
        // tripped a budget or refused still consumed its slot, so the
        // pass's progress must move (issue #211).
        self.tick(name);
        outcome
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

    /// Every string literal the engine's own inventory finds in the image.
    pub async fn strings(&self) -> Result<Vec<KunaString>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::Strings(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Every reference into `address`, from the engine's xref walk.
    pub async fn xrefs_to(&self, address: u64) -> Result<Vec<KunaXref>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::XrefsTo { address, reply })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Every named type the engine's type factory interns; `category`
    /// filters as the retired Ghidra bridge's did, a case-insensitive substring of
    /// the synthesized category.
    pub async fn data_types(&self, category: Option<&str>) -> Result<Vec<KunaDataType>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::DataTypes {
            category: category.map(str::to_string),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// The full field layout of one named structure.
    pub async fn struct_layout(&self, name: &str) -> Result<KunaStructLayout> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::StructLayout {
            name: name.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// The members of one named enumeration.
    pub async fn enum_values(&self, name: &str) -> Result<KunaEnumDefinition> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::EnumValues {
            name: name.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Every labeled, typed global in the engine's symbol table.
    pub async fn data_items(&self) -> Result<Vec<KunaDataItem>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::DataItems(reply))?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// The mapped bytes at `address`.
    pub async fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::ReadMemory {
            address,
            length,
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Set the prototype of the function at `address`, compiling it to a
    /// `prototype 0x<addr> <declaration>` directive.
    ///
    /// The function must exist in the listing — a miss is a named
    /// [`KunaError::FunctionNotFound`] before the plane is touched — and a
    /// declaration the engine's own grammar refuses is a named
    /// [`KunaError::DirectiveRejected`] that leaves the plane untouched. An
    /// accepted prototype takes effect live and persists to the directive
    /// file.
    pub async fn set_function_prototype(&self, address: u64, prototype: &str) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::SetPrototype {
            address,
            prototype: prototype.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Set the type of `variable` in the function at `address`, compiling
    /// it to a `type <func>::<var> <C type>` directive.
    ///
    /// The engine applies the directive on the next decompile of that
    /// function — the decompile loop's own symbol-scoped pass — so the new
    /// type shows in the re-decompiled signature and body.
    pub async fn set_local_variable_type(
        &self,
        address: u64,
        variable: &str,
        type_name: &str,
    ) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::SetLocalType {
            address,
            variable: variable.to_string(),
            type_name: type_name.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Create the structure `name` with `fields`, compiling it to a
    /// `typedef struct` declaration the engine interns live.
    ///
    /// Kuna's C grammar refuses an empty struct body, so a fieldless
    /// create is a named refusal; a field naming an explicit offset is
    /// refused too — the directive plane lays fields out in order.
    pub async fn create_struct(&self, name: &str, fields: &[KunaNewField<'_>]) -> Result<()> {
        if let Some(field) = fields.iter().find(|field| field.offset.is_some()) {
            return Err(KunaError::DirectiveRejected {
                directive: format!("{}: {}", field.name, field.type_name),
                reason: "the directive plane lays fields out in order; an explicit offset has no rendering".to_string(),
            });
        }
        let (reply, answer) = oneshot::channel();
        self.send(Command::CreateStruct {
            name: name.to_string(),
            fields: fields
                .iter()
                .map(|field| (field.name.to_string(), field.type_name.to_string()))
                .collect(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Create the enumeration `name`, `size` bytes wide, with `values`
    /// (member name → value), as a fixed-underlying-type C23 enum.
    pub async fn create_enum(&self, name: &str, values: &[(&str, i64)], size: u32) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::CreateEnum {
            name: name.to_string(),
            values: values
                .iter()
                .map(|(member, value)| (member.to_string(), *value))
                .collect(),
            size,
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Create the typedef `name` as an alias for `base_type`.
    pub async fn create_typedef(&self, name: &str, base_type: &str) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::CreateTypedef {
            name: name.to_string(),
            base_type: base_type.to_string(),
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// Add one field to the structure `struct_name` by regenerating its
    /// owning `typedef struct` record in the plane.
    ///
    /// Kuna refuses to re-body a completed record, so the regenerated
    /// record takes effect on the next load; the live session keeps the
    /// old body until then. A struct the plane holds no record for is a
    /// named [`KunaError::DirectiveRegenerationFailed`], and so is a record
    /// whose text carries a shape the regeneration cannot re-render.
    pub async fn add_struct_field(
        &self,
        struct_name: &str,
        field_name: &str,
        field_type: &str,
        offset: Option<u32>,
    ) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::AddStructField {
            struct_name: struct_name.to_string(),
            field_name: field_name.to_string(),
            field_type: field_type.to_string(),
            offset,
            reply,
        })?;
        answer.await.map_err(|_| KunaError::EngineUnavailable)?
    }

    /// What became of each directive the source carries — the engine's own
    /// per-directive report: `applied` or `rejected`, where a directive not
    /// yet reached reports as rejected with the detail
    /// `not reached by this run` (a local-type directive waits on the
    /// decompile of its function, and a regenerated struct record waits
    /// for the next load).
    pub async fn directive_fates(&self) -> Result<Vec<DirectiveOutcome>> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::DirectiveFates(reply))?;
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
    directive_file: Option<PathBuf>,
    budget: KunaBudget,
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
    // The budgets arm before the handshake, so the first decompile the
    // caller sees is already bounded (issue #211).
    budget.apply(&mut program);
    // The write-back plane opens with the program: an existing file
    // replays through the engine's assertion plane before the handshake,
    // so the session the caller sees already carries its recorded writes.
    // Refusals during that replay are not fatal — the fates report them.
    let mut plane = match directive_file.as_deref() {
        Some(file) => match DirectivePlane::open(file) {
            Ok(plane) => plane,
            Err(error) => {
                let _ = handshake.send(Err(error));
                return;
            }
        },
        None => DirectivePlane::in_memory(),
    };
    if !plane.directives().is_empty() {
        program.program.set_assertions(plane.directives().to_vec());
        kuna_console::assertions::apply_program_scoped(&mut program.program);
    }
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
    // The xref walk is the expensive read; build its index once, lazily, on
    // the first xref-shaped request and keep it for the thread's life.
    let mut xref_index: Option<kuna_analysis::listing::xrefs::XrefIndex> = None;
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
            Command::Strings(reply) => {
                let _ = reply
                    .send(guard("strings", || string_inventory(&path, &container_bytes)).flatten());
            }
            Command::XrefsTo { address, reply } => {
                let _ = reply.send(
                    guard("xrefs_to", || {
                        xrefs_to(&program, &path, &container_bytes, &mut xref_index, address)
                    })
                    .flatten(),
                );
            }
            Command::DataTypes { category, reply } => {
                let _ = reply.send(
                    guard("data_types", || data_types(&program, category.as_deref())).flatten(),
                );
            }
            Command::StructLayout { name, reply } => {
                let _ =
                    reply.send(guard("struct_layout", || struct_layout(&program, &name)).flatten());
            }
            Command::EnumValues { name, reply } => {
                let _ = reply.send(guard("enum_values", || enum_values(&program, &name)).flatten());
            }
            Command::DataItems(reply) => {
                let _ = reply.send(guard("data_items", || data_items(&program)).flatten());
            }
            Command::ReadMemory {
                address,
                length,
                reply,
            } => {
                let _ = reply.send(
                    guard("read_memory", || read_memory(&program, address, length)).flatten(),
                );
            }
            Command::SetPrototype {
                address,
                prototype,
                reply,
            } => {
                let _ = reply.send(
                    guard("set_function_prototype", || {
                        write_prototype(&mut program, &mut plane, address, &prototype)
                    })
                    .flatten(),
                );
            }
            Command::SetLocalType {
                address,
                variable,
                type_name,
                reply,
            } => {
                let _ = reply.send(
                    guard("set_local_variable_type", || {
                        write_local_type(&mut program, &mut plane, address, &variable, &type_name)
                    })
                    .flatten(),
                );
            }
            Command::CreateStruct {
                name,
                fields,
                reply,
            } => {
                let _ = reply.send(
                    guard("create_struct", || {
                        write_create_struct(&mut program, &mut plane, &name, &fields)
                    })
                    .flatten(),
                );
            }
            Command::CreateEnum {
                name,
                values,
                size,
                reply,
            } => {
                let _ = reply.send(
                    guard("create_enum", || {
                        write_create_enum(&mut program, &mut plane, &name, &values, size)
                    })
                    .flatten(),
                );
            }
            Command::CreateTypedef {
                name,
                base_type,
                reply,
            } => {
                let _ = reply.send(
                    guard("create_typedef", || {
                        write_create_typedef(&mut program, &mut plane, &name, &base_type)
                    })
                    .flatten(),
                );
            }
            Command::AddStructField {
                struct_name,
                field_name,
                field_type,
                offset,
                reply,
            } => {
                let _ = reply.send(
                    guard("add_struct_field", || {
                        write_add_struct_field(
                            &mut program,
                            &mut plane,
                            &struct_name,
                            &field_name,
                            &field_type,
                            offset,
                        )
                    })
                    .flatten(),
                );
            }
            Command::DirectiveFates(reply) => {
                let _ = reply.send(Ok(directive_fates(&program)));
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
/// Two kinds of entry are excluded, because neither has a body the engine
/// can render:
///
/// * Kuna's synthetic import placeholders — addresses invented for call
///   naming on a relocatable load, reported as `UndefinedExternal`.
/// * PE import pointer slots. The PE loader registers each IAT slot as a
///   named `FunctionSymbol` so a call through the slot binds to the import
///   name, and a linked PE's slot address is a real mapped address, so
///   provenance alone does not identify it. Kuna's own body predicate,
///   [`kuna_console::engine::ConsoleProgram::is_body_entry`], is what its
///   decompile surfaces consult before lifting, and refusing a slot is what
///   produces "the IAT slot contains a loader-written pointer, not a
///   function body" — so filtering on the same predicate drops exactly the
///   listed names a `decompile` would fail on. A MinGW thunk veneer
///   (`jmp [__imp_puts]`) shares its import's name and stays listed: it is
///   code in `.text`, and it decompiles.
///
/// The seam's `functions` listing therefore answers with functions defined
/// in the image, and imports have their own read. Callers that resolve a
/// callee name to a listing address now answer `0` for an import — the
/// shape the API-mapping lookup already reads as "external, match by name".
fn list_functions(program: &KunaProgram) -> Result<Vec<KunaFunction>> {
    use kuna_console::engine::EntryProvenance;
    let program = &program.program;
    Ok(program
        .function_entries_canonical()
        .into_iter()
        .filter(|entry| entry.provenance != EntryProvenance::UndefinedExternal)
        .filter(|entry| program.is_body_entry(entry.addr.get_offset()))
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
        let reason = result
            .error
            .unwrap_or_else(|| "the engine produced no output".to_string());
        // A budget trip is Kuna's watchdog stopping one function, not the
        // engine failing on it: name the budget so the run degrades per
        // function instead of treating it as an ordinary refusal
        // (issue #211).
        return Err(match budget_trip(&reason) {
            Some(budget) => KunaError::DecompileBudgetExceeded {
                name: name.to_string(),
                budget,
                reason,
            },
            None => KunaError::DecompileFailed {
                name: name.to_string(),
                reason,
            },
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

/// Which per-function budget a Kuna refusal names, if it is a watchdog
/// trip (issue #211).
///
/// Kuna's budget failures carry fixed explain strings from the engine's
/// watchdogs — the flow's instruction bound, the `kuna_fn_budget` deadline,
/// and the `kuna_fnmemory` resident-set limit. Matching them turns a
/// capped function into a named budget failure the run can degrade past,
/// rather than an ordinary decompile failure.
fn budget_trip(error: &str) -> Option<&'static str> {
    if error.contains("Flow exceeded maximum allowable instructions") {
        Some("instruction")
    } else if error.contains("per-function decompile budget exceeded") {
        Some("time")
    } else if error.contains("per-function memory limit exceeded") {
        Some("memory")
    } else {
        None
    }
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

/// The string inventory, over the container bytes captured at load time:
/// the engine's own matcher (`kuna strings`' inventory query) with the
/// `StringLiteralPass`'s own policy — minimum length 5, the 1-byte ASCII
/// and 2-byte UTF-16LE widths, NUL-terminated runs — so every row is also
/// a literal the engine marked up at load.
fn string_inventory(path: &Path, data: &[u8]) -> Result<Vec<KunaString>> {
    use kuna_analysis::analyzers::strings::kuna_stringinv::{self, Query, Termination};
    let file = parse_container(data, path)?;
    let query = Query {
        min_len: 5,
        ascii: true,
        utf8: false,
        utf16: true,
        section: None,
        termination: Termination::Nul,
    };
    Ok(kuna_stringinv::inventory(&file, &query)
        .strings
        .into_iter()
        .map(|found| KunaString {
            address: found.addr,
            value: found.text,
        })
        .collect())
}

/// Every reference into `address`, from the engine's xref walk
/// (`kuna xrefs`): the index is built once from the program's own function
/// inventory over the load-time bytes and cached on the engine thread, and
/// a callable answers across its whole alias class — the veneer and the
/// slot it jumps through — exactly as the engine's own xref query does.
fn xrefs_to(
    program: &KunaProgram,
    path: &Path,
    data: &[u8],
    cache: &mut Option<kuna_analysis::listing::xrefs::XrefIndex>,
    address: u64,
) -> Result<Vec<KunaXref>> {
    use kuna_analysis::listing::xrefs;
    let file = parse_container(data, path)?;
    let program = &program.program;
    let index = match cache {
        Some(index) => index,
        None => {
            let inventory: Vec<u64> = program
                .function_entries_canonical()
                .into_iter()
                .map(|entry| entry.addr.get_offset())
                .collect();
            let seeds = xrefs::discovery_seeds(
                &file,
                &inventory,
                program.arch().analysis_funcstart_patterns,
            );
            cache.insert(xrefs::build(
                &file,
                program.arch(),
                program.arch().translate(),
                &seeds,
            ))
        }
    };
    let names: BTreeMap<u64, String> = program
        .function_entries_canonical()
        .into_iter()
        .map(|entry| (entry.addr.get_offset(), entry.name))
        .collect();
    Ok(index
        .refs_to_unified(address)
        .into_iter()
        .map(|reference| KunaXref {
            address: reference.from,
            function: index
                .function_containing(reference.from)
                .and_then(|entry| names.get(&entry))
                .cloned(),
            kind: Some(reference.kind.as_str().to_string()),
        })
        .collect())
}

/// Every named type the engine's type factory interns, in
/// definition-before-use order. The engine has no Type Manager categories,
/// so the category is synthesized from the type's kind and the path from
/// the category; `category` filters the way the retired Ghidra bridge's did, a
/// case-insensitive substring of the category.
fn data_types(program: &KunaProgram, category: Option<&str>) -> Result<Vec<KunaDataType>> {
    let mut listing: Vec<KunaDataType> = Vec::new();
    for ct in interned_types(program) {
        let name = ct.get_name().to_string();
        if name.is_empty() {
            continue;
        }
        let category = type_category(&ct).to_string();
        listing.push(KunaDataType {
            size: u64::try_from(ct.get_size()).ok(),
            path: format!("/{category}/{name}"),
            category,
            name,
        });
    }
    if let Some(word) = category {
        let word = word.to_lowercase();
        listing.retain(|entry| entry.category.contains(&word));
    }
    Ok(listing)
}

/// The types the factory holds, in the order a definition-before-use walk
/// consumes them — the same order the project decompile's `.h` renders.
fn interned_types(program: &KunaProgram) -> Vec<Rc<kuna_decomp::dtype::Datatype>> {
    program.program.arch().types_impl().dependent_order()
}

/// The category a kind synthesizes for the listing. Core types are
/// vocabulary rather than recovered information, and answer as `builtin`
/// so the recovery scanner skips them like Ghidra's builtins; a typedef
/// answers as `typedef` whatever the type it names, like the bridge's
/// classification.
fn type_category(ct: &kuna_decomp::dtype::Datatype) -> &'static str {
    use kuna_decomp::dtype::{DatatypeKind, flags};
    if ct.flags & flags::coretype != 0 {
        return "builtin";
    }
    if ct.typedef_imm.is_some() {
        return "typedef";
    }
    match &ct.kind {
        DatatypeKind::Base | DatatypeKind::Void | DatatypeKind::Unknown => "builtin",
        DatatypeKind::Struct { .. } => "struct",
        DatatypeKind::Union { .. } => "union",
        DatatypeKind::Enum { .. } => "enum",
        DatatypeKind::Pointer { .. } => "pointer",
        DatatypeKind::Array { .. } => "array",
        _ => "other",
    }
}

/// One named type from the factory, by exact name.
fn find_type(program: &KunaProgram, name: &str) -> Result<Rc<kuna_decomp::dtype::Datatype>> {
    interned_types(program)
        .into_iter()
        .find(|ct| ct.get_name() == name)
        .ok_or_else(|| KunaError::TypeNotFound {
            name: name.to_string(),
        })
}

/// The full field layout of one named structure. A bitfield-bearing struct
/// answers its bitfields as rows too, each carrying its container's byte
/// offset and byte size — the extent a reference or variable sees — beside
/// the byte-aligned fields.
fn struct_layout(program: &KunaProgram, name: &str) -> Result<KunaStructLayout> {
    use kuna_decomp::dtype::DatatypeKind;
    let ct = find_type(program, name)?;
    let (fields, bitfields) = match &ct.kind {
        DatatypeKind::Struct { field, bitfield } => (field, bitfield),
        _ => {
            return Err(KunaError::NotAStruct {
                name: name.to_string(),
            });
        }
    };
    let mut layout: Vec<KunaStructField> = fields
        .iter()
        .map(|field| KunaStructField {
            offset: field.offset.max(0) as u64,
            size: field.field_type.get_size().max(0) as u64,
            type_name: field.field_type.get_name().to_string(),
            field_name: field.name.clone(),
        })
        .collect();
    for bitfield in bitfields {
        layout.push(KunaStructField {
            offset: bitfield.byte_offset.max(0) as u64,
            size: bitfield.byte_size.max(0) as u64,
            type_name: bitfield.field_type.get_name().to_string(),
            field_name: bitfield.name.clone(),
        });
    }
    layout.sort_by_key(|row| (row.offset, row.field_name.clone()));
    Ok(KunaStructLayout {
        name: ct.get_name().to_string(),
        size: ct.get_size().max(0) as u64,
        alignment: ct.alignment.max(0) as u64,
        fields: layout,
    })
}

/// The members of one named enumeration, valued exactly as the engine's
/// own C rendering of the type spells them (the `.h` of a project
/// decompile): a signed enum's members arrive sign-extended, an unsigned
/// enum's as their raw value.
fn enum_values(program: &KunaProgram, name: &str) -> Result<KunaEnumDefinition> {
    use kuna_decomp::dtype::{DatatypeKind, type_metatype};
    let ct = find_type(program, name)?;
    let namemap = match &ct.kind {
        DatatypeKind::Enum { namemap } => namemap,
        _ => {
            return Err(KunaError::NotAnEnum {
                name: name.to_string(),
            });
        }
    };
    let size = ct.get_size();
    let signed = ct.get_metatype() == type_metatype::TYPE_INT;
    let members = namemap
        .iter()
        .map(|(value, member)| KunaEnumMember {
            name: member.clone(),
            value: if signed && (1..=8).contains(&size) {
                kuna_base::address::sign_extend(*value as i64, size * 8 - 1)
            } else {
                *value as i64
            },
        })
        .collect();
    Ok(KunaEnumDefinition {
        name: ct.get_name().to_string(),
        size: size.max(0) as u64,
        members,
    })
}

/// Every labeled, typed global in the engine's symbol table: the same
/// scoped walk the console's own data-symbol read makes, keeping the
/// applied type's name for the seam's `type_name` and dropping code-typed
/// placeholders the way that read does.
fn data_items(program: &KunaProgram) -> Result<Vec<KunaDataItem>> {
    use kuna_decomp::dtype::type_metatype;
    let program = &program.program;
    let arch = program.arch();
    let Some(scope) = arch.symboltab.get_global_scope() else {
        return Ok(Vec::new());
    };
    let Some(data_space) = arch.manage().get_default_data_space() else {
        return Ok(Vec::new());
    };
    let space_index = data_space.get_index() as usize;
    Ok(arch
        .symboltab
        .scope_space_symbol_specs(scope, space_index)
        .into_iter()
        .filter(|(_, ct, _, _)| ct.get_metatype() != type_metatype::TYPE_CODE)
        .map(|(label, ct, address, _)| KunaDataItem {
            label,
            address: address.get_offset(),
            type_name: ct.get_name().to_string(),
            length: ct.get_size().max(0) as u64,
        })
        .collect())
}

/// The mapped bytes at `address`, from the program's own load image; an
/// unmapped range is a named miss, never a zero-filled answer.
fn read_memory(program: &KunaProgram, address: u64, length: usize) -> Result<Vec<u8>> {
    program
        .program
        .read_bytes(address, length)
        .ok_or(KunaError::MemoryUnmapped { address, length })
}

// ============================================================
// The write-back plane: one write-seam call, one directive
// ============================================================

/// The function at a user-facing address, or a named miss. Write commands
/// address functions the way the seam does — by the address the listing
/// reports — and the plane only ever records what the program can honor.
fn entry_at(program: &KunaProgram, address: u64) -> Result<kuna_console::engine::FunctionEntry> {
    use kuna_console::engine::EntrySelector;
    program
        .program
        .resolve_entry(&EntrySelector::Numeric(address))
        .map_err(|_| KunaError::FunctionNotFound {
            name: format!("0x{address:x}"),
        })
}

/// The data organization the C grammar reads — the same split the
/// engine's own assertion apply uses.
fn grammar_org(program: &KunaProgram) -> kuna_console::grammar::DataOrg {
    let (addr_size, word_size) = program.program.arch().data_org();
    kuna_console::grammar::DataOrg {
        addr_size,
        word_size,
    }
}

/// A type text the engine's own C type grammar refuses, named as the
/// declaration the caller handed the seam.
fn reject_type_text(type_name: &str, error: &kuna_base::error::KunaError) -> KunaError {
    KunaError::DirectiveRejected {
        directive: type_name.to_string(),
        reason: error.explain().to_string(),
    }
}

/// Snapshot of the engine's installed directive set and its per-directive
/// report, so a re-install can carry the fates across.
type FateSnapshot = (
    Vec<kuna_console::assertions::Directive>,
    Vec<kuna_console::assertions::Outcome>,
);

fn snapshot_fates(program: &KunaProgram) -> FateSnapshot {
    (
        program.program.assertions().to_vec(),
        program.program.assertion_outcomes(),
    )
}

/// `set_assertions` replaces the whole set and resets every outcome slot,
/// but a directive's effect outlives the write that installed it — so
/// carry each unchanged directive's real fate onto its new slot. Only a
/// directive that changed (or is new) waits unclaimed; the engine's own
/// placeholder reports the wait as `rejected: not reached by this run`.
fn carry_fates(program: &mut KunaProgram, snapshot: &FateSnapshot) {
    use kuna_console::assertions::unclaimed;
    let (old_directives, old_outcomes) = snapshot;
    for (i, directive) in program
        .program
        .assertions()
        .to_vec()
        .into_iter()
        .enumerate()
    {
        let (Some(old), Some(outcome)) = (old_directives.get(i), old_outcomes.get(i)) else {
            continue;
        };
        if old == &directive && outcome != &unclaimed(old) {
            program.program.set_assertion_outcome(i, outcome.clone());
        }
    }
}

/// Install the plane's current set on the engine, keeping the fates of the
/// directives that did not change.
fn install_plane(program: &mut KunaProgram, plane: &DirectivePlane) {
    let snapshot = snapshot_fates(program);
    program.program.set_assertions(plane.directives().to_vec());
    carry_fates(program, &snapshot);
}

/// Apply the directive at `index` — and only it — through the engine's own
/// program-scoped pass, then install the full plane set with the fates
/// carried: applied persists to the directive file, rejected rolls the
/// plane back and arrives as a named [`KunaError::DirectiveRejected`] —
/// the engine's reason, not calxgloss's guess at one.
fn apply_and_report(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    index: usize,
) -> Result<()> {
    let snapshot = snapshot_fates(program);
    let directive = plane.directives()[index].clone();
    program.program.set_assertions(vec![directive]);
    kuna_console::assertions::apply_program_scoped(&mut program.program);
    let outcome = program
        .program
        .assertion_outcomes()
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            kuna_console::assertions::unclaimed(plane.directives().last().expect("just installed"))
        });
    if outcome.status != "applied" {
        plane.pop();
        program.program.set_assertions(snapshot.0.clone());
        carry_fates(program, &snapshot);
        return Err(KunaError::DirectiveRejected {
            directive: outcome.directive,
            reason: outcome
                .detail
                .unwrap_or_else(|| "the engine refused the directive".to_string()),
        });
    }
    plane.save()?;
    install_plane(program, plane);
    program.program.set_assertion_outcome(index, outcome);
    Ok(())
}

/// `set_function_prototype` → push, apply live, report.
fn write_prototype(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    address: u64,
    prototype: &str,
) -> Result<()> {
    entry_at(program, address)?;
    let directive = directives::prototype_directive(address, prototype);
    let index = plane.push(directive);
    apply_and_report(program, plane, index)
}

/// `set_local_variable_type` → validate, push, install for the decompile
/// loop. The engine applies a `type` directive when it next decompiles
/// the named function, so there is nothing to apply here — installing it
/// is the whole live effect, and until that decompile the fates report the
/// wait as `rejected: not reached by this run`.
fn write_local_type(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    address: u64,
    variable: &str,
    type_name: &str,
) -> Result<()> {
    let entry = entry_at(program, address)?;
    if let Err(error) = kuna_console::grammar::parse_type(
        type_name,
        program.program.arch().types(),
        grammar_org(program),
    ) {
        return Err(reject_type_text(type_name, &error));
    }
    let directive = directives::local_type_directive(&entry.name, variable, type_name);
    plane.push(directive);
    plane.save()?;
    install_plane(program, plane);
    Ok(())
}

/// `create_struct` → push, intern live, report. Kuna's C grammar refuses
/// an empty struct body, and the plane lays fields out in order, so an
/// explicit offset has no honest rendering — both are named refusals
/// before the plane is touched.
fn write_create_struct(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    name: &str,
    fields: &[(String, String)],
) -> Result<()> {
    if fields.is_empty() {
        return Err(KunaError::DirectiveRejected {
            directive: format!("typedef struct {name} {{ }};"),
            reason: "Kuna's C grammar refuses an empty struct body; create the struct with its first field".to_string(),
        });
    }
    let owned: Vec<KunaNewField<'_>> = fields
        .iter()
        .map(|(field_name, type_name)| KunaNewField::new(field_name, type_name))
        .collect();
    let directive = directives::struct_directive(name, &owned);
    let index = plane.push(directive);
    apply_and_report(program, plane, index)
}

/// `create_enum` → push, intern live, report.
fn write_create_enum(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    name: &str,
    values: &[(String, i64)],
    size: u32,
) -> Result<()> {
    let borrowed: Vec<(&str, i64)> = values.iter().map(|(m, v)| (m.as_str(), *v)).collect();
    let directive = directives::enum_directive(name, &borrowed, size);
    let index = plane.push(directive);
    apply_and_report(program, plane, index)
}

/// `create_typedef` → push, intern live, report.
fn write_create_typedef(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    name: &str,
    base_type: &str,
) -> Result<()> {
    let directive = directives::typedef_directive(name, base_type);
    let index = plane.push(directive);
    apply_and_report(program, plane, index)
}

/// `add_struct_field` → regenerate the owning record in place.
///
/// Kuna refuses to re-body a completed record, so the regenerated record
/// is not applied to the live session — it takes effect on the next load,
/// which is exactly where the replayed plane re-creates the struct whole.
/// A struct the plane holds no record for cannot be re-bodied honestly:
/// appending a second record would collide with the first on replay, so
/// that is a named [`KunaError::DirectiveRegenerationFailed`], and so is a
/// record whose text carries a shape the regeneration cannot re-render.
fn write_add_struct_field(
    program: &mut KunaProgram,
    plane: &mut DirectivePlane,
    struct_name: &str,
    field_name: &str,
    field_type: &str,
    offset: Option<u32>,
) -> Result<()> {
    if offset.is_some() {
        return Err(KunaError::DirectiveRejected {
            directive: format!("{field_name}: {field_type} @{offset:?}"),
            reason:
                "the directive plane lays fields out in order; an explicit offset has no rendering"
                    .to_string(),
        });
    }
    if let Err(error) = kuna_console::grammar::parse_type(
        field_type,
        program.program.arch().types(),
        grammar_org(program),
    ) {
        return Err(reject_type_text(field_type, &error));
    }
    let Some(index) = plane.struct_record_index(struct_name) else {
        find_type(program, struct_name)?;
        return Err(KunaError::DirectiveRegenerationFailed {
            name: struct_name.to_string(),
            reason: "the directive plane holds no record for this type; calxgloss can only re-body the records it wrote".to_string(),
        });
    };
    let existing: Vec<(&str, &str)> = match plane.struct_record(struct_name) {
        Some((_, fields)) => fields,
        None => {
            return Err(KunaError::DirectiveRegenerationFailed {
                name: struct_name.to_string(),
                reason: "the record carries a shape the plane cannot re-render (a bitfield)"
                    .to_string(),
            });
        }
    };
    let mut fields: Vec<(String, String)> = existing
        .into_iter()
        .map(|(type_name, name)| (type_name.to_string(), name.to_string()))
        .collect();
    fields.push((field_type.to_string(), field_name.to_string()));
    let rendered: Vec<(&str, &str)> = fields
        .iter()
        .map(|(type_name, name)| (type_name.as_str(), name.as_str()))
        .collect();
    plane.replace(
        index,
        directives::struct_record_directive(struct_name, &rendered),
    );
    plane.save()?;
    install_plane(program, plane);
    Ok(())
}

/// The engine's per-directive report, lifted to plain records.
fn directive_fates(program: &KunaProgram) -> Vec<DirectiveOutcome> {
    program
        .program
        .assertion_outcomes()
        .into_iter()
        .map(|outcome| DirectiveOutcome {
            directive: outcome.directive,
            status: outcome.status.to_string(),
            detail: outcome.detail,
        })
        .collect()
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
        // The message says the panic was caught at the seam, so the
        // process survives the engine's own bug.
        assert!(fault.to_string().contains("caught at the engine seam"));
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

    // The reads the seam maps, answered over the fixture. The engine-native
    // actor path is exercised end to end in the two `kuna_scan.rs` test
    // files; these tests drive the handlers directly so a wrong answer is
    // named at the function that produced it.

    /// The fixture program, loaded for handler-level reads.
    fn fixture_program() -> KunaProgram {
        let fixture =
            calxgloss_testfixtures::load_target().expect("the fixture target builds and validates");
        engine::load(fixture.path()).expect("the fixture must load")
    }

    /// The fixture path and the container bytes a load captured beside it.
    fn fixture_bytes() -> (PathBuf, Vec<u8>) {
        let fixture =
            calxgloss_testfixtures::load_target().expect("the fixture target builds and validates");
        let path = fixture.path().to_path_buf();
        (
            path.clone(),
            read_file(&path).expect("the fixture is readable"),
        )
    }

    /// Intern C declarations through the engine's own assertion plane —
    /// the same `typedef` directive the console applies before decompile —
    /// so the type reads have structures, enums, and typedefs to answer.
    fn declare(program: &mut KunaProgram, declarations: &[&str]) {
        use kuna_console::assertions::{Body, Directive};
        program.program.set_assertions(
            declarations
                .iter()
                .map(|decl| Directive {
                    raw: (*decl).to_string(),
                    body: Body::Typedef {
                        decl: (*decl).to_string(),
                    },
                })
                .collect(),
        );
        kuna_console::assertions::apply_program_scoped(&mut program.program);
    }

    fn declared_fixture() -> KunaProgram {
        let mut program = fixture_program();
        declare(
            &mut program,
            &[
                "struct tagPOINT { int x; int y; };",
                "enum COLOR { RED = 1, GREEN = 2, BLUE = -3 };",
                "struct BITS { unsigned int a : 3; unsigned int b : 5; };",
                "typedef unsigned long ULONG;",
            ],
        );
        program
    }

    #[test]
    fn the_type_listing_classifies_the_interned_types_by_kind() {
        let program = declared_fixture();
        let types = data_types(&program, None).expect("the type listing answers");

        let find = |name: &str| types.iter().find(|entry| entry.name == name);
        // Core vocabulary is skipped as builtin, like Ghidra's builtins —
        // and the engine names them Ghidra's way (`int4`, not `int`).
        assert_eq!(find("int4").map(|e| e.category.as_str()), Some("builtin"));
        assert_eq!(
            find("tagPOINT").map(|e| e.category.as_str()),
            Some("struct")
        );
        assert_eq!(find("COLOR").map(|e| e.category.as_str()), Some("enum"));
        assert_eq!(find("BITS").map(|e| e.category.as_str()), Some("struct"));
        assert_eq!(find("ULONG").map(|e| e.category.as_str()), Some("typedef"));
        // The path is synthesized from the category, and no entry is anonymous.
        for entry in &types {
            assert!(
                !entry.name.is_empty(),
                "anonymous types are skipped: {entry:?}"
            );
            assert_eq!(entry.path, format!("/{}/{}", entry.category, entry.name));
        }

        // The category filter answers like the bridge's: a case-insensitive
        // substring of the category.
        let structs = data_types(&program, Some("Struct")).expect("the filtered listing answers");
        assert!(structs.iter().any(|entry| entry.name == "tagPOINT"));
        assert!(
            structs
                .iter()
                .all(|entry| entry.category.contains("struct")),
            "the filter matched outside its bucket: {structs:?}"
        );
    }

    #[test]
    fn struct_layout_answers_fields_and_bitfields() {
        let program = declared_fixture();
        let point = struct_layout(&program, "tagPOINT").expect("a declared struct answers layout");
        assert_eq!(point.size, 8);
        let fields: Vec<(&str, u64, &str)> = point
            .fields
            .iter()
            .map(|field| {
                (
                    field.field_name.as_str(),
                    field.offset,
                    field.type_name.as_str(),
                )
            })
            .collect();
        assert_eq!(fields, vec![("x", 0, "int4"), ("y", 4, "int4")]);

        // A bitfield-bearing struct answers its bitfields as rows too, each
        // carrying the byte extent a reference sees.
        let bits = struct_layout(&program, "BITS").expect("a bitfield struct answers layout");
        assert_eq!(bits.size, 4);
        let rows: Vec<(&str, u64, u64, &str)> = bits
            .fields
            .iter()
            .map(|field| {
                (
                    field.field_name.as_str(),
                    field.offset,
                    field.size,
                    field.type_name.as_str(),
                )
            })
            .collect();
        assert_eq!(rows, vec![("a", 0, 1, "uint4"), ("b", 0, 1, "uint4")]);
    }

    #[test]
    fn enum_values_answer_as_the_engine_renders_the_type() {
        let program = declared_fixture();
        let color = enum_values(&program, "COLOR").expect("a declared enum answers members");
        assert_eq!(color.size, 4);
        // A signed enum's members arrive sign-extended — the same values the
        // `.h` of a project decompile prints — so BLUE is -3, not 0xfffffffd.
        let members: Vec<(&str, i64)> = color
            .members
            .iter()
            .map(|member| (member.name.as_str(), member.value))
            .collect();
        assert!(members.contains(&("RED", 1)), "got {members:?}");
        assert!(members.contains(&("GREEN", 2)), "got {members:?}");
        assert!(members.contains(&("BLUE", -3)), "got {members:?}");
    }

    #[test]
    fn a_type_or_kind_miss_and_an_unmapped_read_are_named_misses() {
        let program = declared_fixture();
        assert!(
            matches!(struct_layout(&program, "no_such_type"),
                Err(KunaError::TypeNotFound { name }) if name == "no_such_type"),
            "an unknown name is a named type miss"
        );
        assert!(
            matches!(struct_layout(&program, "COLOR"),
                Err(KunaError::NotAStruct { name }) if name == "COLOR"),
            "an enum probed for a layout is a kind miss"
        );
        assert!(
            matches!(enum_values(&program, "tagPOINT"),
                Err(KunaError::NotAnEnum { name }) if name == "tagPOINT"),
            "a struct probed for members is a kind miss"
        );
        assert!(
            matches!(read_memory(&program, 1 << 48, 4),
                Err(KunaError::MemoryUnmapped { address, length }) if address == 1 << 48 && length == 4),
            "an unmapped range is a named miss, never a zero-filled answer"
        );
    }

    #[tokio::test]
    async fn the_container_and_program_reads_answer_over_the_fixture() {
        let source = KunaSource::load(fixture_bytes().0.as_path())
            .expect("the fixture must load for scanning with Kuna");

        // The string inventory finds every literal the fixture promises.
        let strings = source
            .strings()
            .await
            .expect("the string inventory answers");
        for literal in calxgloss_testfixtures::STRING_LITERALS {
            assert!(
                strings.iter().any(|found| &found.value == literal),
                "the inventory should find {literal:?}, got {:?}",
                strings.iter().map(|s| &s.value).collect::<Vec<_>>(),
            );
        }

        // The program's own load image answers memory reads; the PE header
        // is the first mapped thing in the image.
        let base = source.image_base().await.expect("the image base answers");
        let header = source
            .read_memory(base, 2)
            .await
            .expect("the header is mapped");
        assert_eq!(header, b"MZ");

        // At least one fixture literal is referenced from a named function,
        // and the xref walk names the referencing function and kind.
        let mut referenced = None;
        for string in &strings {
            let xrefs = source
                .xrefs_to(string.address)
                .await
                .expect("the xref read answers");
            if !xrefs.is_empty() {
                referenced = Some((string.clone(), xrefs));
                break;
            }
        }
        let (string, xrefs) = referenced.expect("a fixture literal is referenced by code");
        assert!(
            xrefs.iter().all(|xref| xref.address >= base),
            "xref sites are in-image addresses: {xrefs:?}"
        );
        assert!(
            xrefs
                .iter()
                .any(|xref| xref.function.is_some() && xref.kind.is_some()),
            "the walk names the referencing function and kind for {string:?}: {xrefs:?}"
        );

        // The symbol table answers data items with their applied type names.
        let items = source
            .data_items()
            .await
            .expect("the data-item read answers");
        for item in &items {
            assert!(
                !item.label.is_empty(),
                "a labeled global carries a label: {item:?}"
            );
            assert!(item.address >= base, "a global sits in the image: {item:?}");
        }
    }

    #[test]
    fn the_listing_drops_pe_import_pointer_slots_and_keeps_their_thunks() {
        // The PE loader names each IAT slot with its import name so a call
        // through the slot binds to the import, and names the MinGW thunk
        // veneer that jumps through it. Only the veneer has a body: the slot
        // holds a pointer the run-time loader writes, which is why Kuna's
        // decompile refuses one. A listing that carried the slot handed every
        // consumer a read that cannot succeed — the call-graph build warned
        // once per import over a 32-bit MSVC PE, whose imports carry no veneer
        // at all, so the slot is the only entry the import name has.
        let program = fixture_program();
        let listed = list_functions(&program).expect("the fixture listing");
        let canonical = program.program.function_entries_canonical();

        // The fixture calls through the IAT, so the engine does name its
        // slots and the filter has work to do.
        let slots: Vec<_> = canonical
            .iter()
            .filter(|entry| !program.program.is_body_entry(entry.addr.get_offset()))
            .collect();
        assert!(
            !slots.is_empty(),
            "the fixture's canonical enumeration names IAT slots, or this test pins nothing"
        );
        for slot in &slots {
            let address = program.program.output_address_offset(&slot.addr);
            assert!(
                !listed.iter().any(|function| function.address == address),
                "the import slot {} at {address:#x} is not a listed function",
                slot.name,
            );
        }

        // And nothing else is dropped: the listing is exactly the canonical
        // entries the engine will lift a body from.
        let bodies = canonical.iter().filter(|entry| {
            entry.provenance != kuna_console::engine::EntryProvenance::UndefinedExternal
                && program.program.is_body_entry(entry.addr.get_offset())
        });
        assert_eq!(
            listed.len(),
            bodies.count(),
            "the listing is the canonical entries with a body"
        );
    }

    // The pass heartbeat and the decompile budgets (issue #211).

    #[tokio::test]
    async fn heartbeat_beats_per_decompile_only_while_a_kuna_pass_is_active() {
        // One beat per completed decompile inside the pass,
        // resolved names, and nothing outside it.
        let (path, _) = fixture_bytes();
        let source = KunaSource::load(&path).expect("the fixture must load");
        let events = TranslationEvents::new(64);
        let mut rx = events.subscribe();
        let names = calxgloss_testfixtures::EXPORT_NAMES;

        source.begin_pass("fixture_target.dll", "type inference", &events);
        source.note_worklist(2);
        source
            .decompile_function(names[0])
            .await
            .expect("the first fixture export decompiles");
        source
            .decompile_function(names[1])
            .await
            .expect("the second fixture export decompiles");
        source.end_pass();
        source
            .decompile_function(names[2])
            .await
            .expect("the third fixture export decompiles");

        let beats: Vec<ProgressEvent> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(beats.len(), 2, "one beat per decompile inside the pass");
        match &beats[0] {
            ProgressEvent::BatchProgress {
                binary,
                pass,
                function,
                index,
                total,
            } => {
                assert_eq!(binary.as_str(), "fixture_target.dll");
                assert_eq!(pass, "type inference");
                assert_eq!(function, names[0]);
                assert_eq!(*index, 1);
                assert_eq!(*total, 2);
            }
            other => panic!("expected BatchProgress, got {other:?}"),
        }
        match &beats[1] {
            ProgressEvent::BatchProgress {
                function,
                index,
                total,
                ..
            } => {
                assert_eq!(function, names[1]);
                assert_eq!(*index, 2);
                assert_eq!(*total, 2);
            }
            other => panic!("expected BatchProgress, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_budget_capped_function_fails_with_a_named_budget_error() {
        // One instruction of flow budget cannot cover any real fixture
        // body: the function fails by name, the run survives, and the
        // error names the knob to raise and the engine to fall back to.
        let (path, _) = fixture_bytes();
        let source = KunaSource::load_with_budget(
            &path,
            None,
            KunaBudget {
                max_instructions: Some(1),
                ..KunaBudget::default()
            },
        )
        .expect("the fixture loads with a budget armed");
        let error = source
            .decompile_function("fixture_describe")
            .await
            .expect_err("a one-instruction budget must cap the function");
        match &error {
            KunaError::DecompileBudgetExceeded { name, budget, .. } => {
                assert_eq!(name, "fixture_describe");
                assert_eq!(budget, &"instruction", "the flow bound tripped: {error}");
            }
            other => panic!("expected a DecompileBudgetExceeded, got {other:?}"),
        }
        let message = error.to_string();
        assert!(
            message.contains("[analysis]") && message.contains("raise the budget"),
            "the message names the knob to raise: {message}"
        );
        // The rest of the run degrades past it, not into a hang: an
        // unbudgeted read still answers over the same source.
        source
            .image_base()
            .await
            .expect("the source still answers after one function tripped");
    }

    #[test]
    fn a_time_budget_trip_is_named_as_a_time_budget() {
        // The wall-clock watchdog is armed on the architecture and checked
        // cooperatively at the drive's loop boundaries; a spent deadline
        // fails the function with Kuna's own budget message, which the
        // seam names as the time budget.
        let mut program = fixture_program();
        program.program.arch_mut().kuna_fn_budget = Some(Duration::ZERO);
        let error = decompile(&mut program, "fixture_tick")
            .expect_err("a spent deadline must cap the function");
        match &error {
            KunaError::DecompileBudgetExceeded {
                name,
                budget,
                reason,
            } => {
                assert_eq!(name, "fixture_tick");
                assert_eq!(budget, &"time", "the deadline tripped: {reason}");
                assert!(
                    reason.contains("per-function decompile budget exceeded"),
                    "Kuna's own explanation is carried: {reason}"
                );
            }
            other => panic!("expected a DecompileBudgetExceeded, got {other:?}"),
        }
    }

    #[test]
    fn budget_trips_are_named_and_ordinary_refusals_are_not() {
        // The three watchdogs Kuna's engine reports, and one refusal that
        // is not a trip at all.
        assert_eq!(
            budget_trip("Flow exceeded maximum allowable instructions"),
            Some("instruction")
        );
        assert_eq!(
            budget_trip("per-function decompile budget exceeded (120 s)"),
            Some("time")
        );
        assert_eq!(
            budget_trip("per-function memory limit exceeded (512 MiB)"),
            Some("memory")
        );
        assert_eq!(
            budget_trip("Could not follow flow into unimplemented instruction"),
            None,
            "an ordinary engine refusal stays an ordinary failure"
        );
    }
}
