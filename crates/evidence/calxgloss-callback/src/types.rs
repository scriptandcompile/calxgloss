//! Core data types for callback and function-pointer table information.
//!
//! This module holds the serialized shape of everything the callback
//! detectors produce:
//!
//! - `FpArrayCall`: a call through an indexed function-pointer table —
//!   the shape Ghidra decompiles out of `*(handlers[i])(args)`.
//! - `CallbackRegistration`: a call to a recognized registration function
//!   with its callback argument bound — the `register_callback(fp)` shape.
//! - `JumpTable`: a call through a table of function addresses at a
//!   computed index — the shape Ghidra leaves behind for
//!   `jmp [table + index*N]`.
//! - `PluginArchitecture`: a dynamic-load shape — a loader pair
//!   (`LoadLibrary`/`GetProcAddress`, `dlopen`/`dlsym`), a plugin
//!   entry-point name, and the host API table passed into one.
//! - `CallbackChain`: a callback registered in one function and
//!   called in another — the lifecycle the per-body detectors each
//!   saw only half of — read by the cross-function pass over the
//!   bodies the scan keeps.
//! - `CallbackFinding`: the union over the five record kinds — one
//!   finding whichever detector or pass made it — serde-tagged by
//!   `kind`.
//! - `CallbackResult`, `ScanMetadata`: the persisted per-binary result
//!   and its scan provenance.
//!
//! All types derive `Serialize`/`Deserialize`.

// `ScanMetadata` is the shared per-binary scan provenance and `Confidence`
// the shared 0–100 evidence score; both are re-exported so consumers name
// them through this crate, matching the typesdb, typeinfer, algorithm,
// memory, and sync convention.
pub use calxgloss_types::{Confidence, ScanMetadata};
use serde::{Deserialize, Serialize};

// ============================================================
// Function-pointer array calls
// ============================================================

/// One function-pointer array call observation about one function, with
/// the evidence behind it.
///
/// A record says the function calls through the indexed table named by
/// [`table`](Self::table) — a call shaped `(*handlers[i])(args)`, where
/// the callee is an element of a function-pointer array rather than a
/// named function — which reads like [`suggestion`](Self::suggestion):
/// an array of boxed closures, `Vec<Box<dyn Fn(...)>>`, so the handler
/// table survives translation as data the Rust compiler can check
/// instead of an opaque indirect call. The call line is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation prompt)
/// can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FpArrayCall {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The table whose indexed element is called, e.g. `handlers`.
    pub table: String,
    /// The Rust pattern the call suggests, e.g.
    /// `Vec<Box<dyn Fn(...)>>`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the indexed
    /// indirect call — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Callback registrations
// ============================================================

/// One callback-registration observation about one function, with the
/// evidence behind it.
///
/// A record says the function calls a recognized registration function —
/// [`registration`](Self::registration), spelled e.g.
/// `register_callback` — and passes it a named callback the finding
/// binds in [`callback`](Self::callback), a function reference or
/// address-of the decompiler names directly. The registration reads like
/// [`suggestion`](Self::suggestion): a `Box<dyn Fn(...)>` closure stored
/// or passed where the original kept a raw function pointer, so the
/// callback boundary survives translation. The registration line is kept
/// as [`evidence`](Self::evidence) so a reviewer (or a translation
/// prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackRegistration {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The registration call spelling, e.g. `register_callback`.
    pub registration: String,
    /// The callback argument the registration binds, e.g. `my_handler`
    /// as written in `register_callback(my_handler)`.
    pub callback: String,
    /// The Rust pattern the registration suggests, e.g.
    /// `Box<dyn Fn(...)>`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the registration
    /// call — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Jump tables
// ============================================================

/// One jump-table dispatch observation about one function, with the
/// evidence behind it.
///
/// A record says the function dispatches through the address table named
/// by [`table`](Self::table) at the computed [`index`](Self::index) —
/// the shape Ghidra leaves behind for `jmp [table + index*N]`, a call
/// through a table of function addresses typically bracketed by a bounds
/// check or a switch over computed cases. When the bounds check or
/// switch is visible, [`target_count`](Self::target_count) carries how
/// many entries the dispatch spans. The dispatch reads like
/// [`suggestion`](Self::suggestion): a Rust `match` over the index at
/// three or more targets, or a function-pointer array when the table is
/// data-driven. The call line is kept as [`evidence`](Self::evidence) so
/// a reviewer (or a translation prompt) can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTable {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The address table the dispatch reads through, e.g.
    /// `DAT_1400a1b60`.
    pub table: String,
    /// The computed index expression, e.g. `uVar2`.
    pub index: String,
    /// How many entries the dispatch spans, read from the bounds check
    /// or switch beside it, when one was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_count: Option<usize>,
    /// The Rust pattern the dispatch suggests, e.g.
    /// `match index { ... }`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the indexed table
    /// call — kept so a reviewer (or a translation prompt) can check the
    /// reasoning.
    pub evidence: String,
}

// ============================================================
// Plugin architectures
// ============================================================

/// One plugin-architecture observation about one function, with the
/// evidence behind it.
///
/// A record says the function carries a dynamic-loading shape: the
/// loader pair [`load`](Self::load) and [`resolve`](Self::resolve) —
/// `LoadLibrary`/`GetProcAddress` or `dlopen`/`dlsym` — loading a
/// module and resolving entry points through it, and/or a direct call
/// to a configured plugin entry-point name
/// ([`entry_point`](Self::entry_point), spelled e.g. `Plugin_Init`)
/// that takes the host API table named in [`host_table`](Self::host_table)
/// as its argument. A full load-and-resolve pair reads at
/// [`confidence`](Self::confidence) 70; a lone resolve call or a lone
/// entry-point name is a fragment, kept at 60. The shape reads like
/// [`suggestion`](Self::suggestion): a trait-object plugin boundary —
/// a `Box<dyn Plugin>` handed out by a loader crate — so the plugin
/// contract survives translation instead of collapsing into opaque
/// loader calls. The loader call line is kept as
/// [`evidence`](Self::evidence) so a reviewer (or a translation prompt)
/// can check the reasoning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginArchitecture {
    /// The function the record is about, e.g. `FUN_18003ab00`.
    pub function: String,
    /// The module-load call spelling the body resolves through, e.g.
    /// `LoadLibrary`, when a load call was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<String>,
    /// The entry-point-resolve call spelling, e.g. `GetProcAddress`,
    /// when a resolve call was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve: Option<String>,
    /// The plugin entry-point name the body calls directly, e.g.
    /// `Plugin_Init`, when one was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<String>,
    /// The host API table passed into the entry point — a struct of
    /// function pointers — e.g. `host_api`, when one was visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_table: Option<String>,
    /// The Rust pattern the shape suggests, e.g.
    /// `Box<dyn Plugin> (loader crate)`.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The decompiled line that supports the record — the loader call
    /// for a full pair, the lone resolve or entry-point call for a
    /// fragment — kept so a reviewer (or a translation prompt) can
    /// check the reasoning.
    pub evidence: String,
}

// ============================================================
// Callback chains
// ============================================================

/// One cross-function callback-chain observation about one function,
/// with the evidence behind it.
///
/// A record says a callback registered in one function — the name the
/// registration detector binds at a recognized registration call — is
/// called in another kept body: either its own spelling stands as a
/// direct call target in the partner body, or the name the
/// registration site names is a configured table and the partner body
/// dispatches through that same [`table`](Self::table) — one
/// callback's lifecycle spanning two bodies, each of which the
/// per-function detectors saw only half of. The finding is attached
/// to the earlier of the two functions in listing order and names the
/// other as [`partner`](Self::partner); the callback rides in
/// [`callback`](Self::callback) and the table it is called through,
/// when the chain runs through one, in [`table`](Self::table). Both
/// ends are explicit body evidence, so the record reads at
/// [`confidence`](Self::confidence) 70 — level with an in-body
/// registration — and reads like [`suggestion`](Self::suggestion):
/// one boxed closure shared across the boundary. Both ends' call
/// lines ride as [`evidence`](Self::evidence) — the registration line
/// and the call line — so a reviewer (or a translation prompt) can
/// check the reasoning against both bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackChain {
    /// The function the record is about — the earlier of the pair in
    /// listing order, whichever end made the registration.
    pub function: String,
    /// The other function in the chain: the one that called when this
    /// one registered, or registered when this one called.
    pub partner: String,
    /// The callback the chain carries, spelled as the registration
    /// bound it, e.g. `my_handler`.
    pub callback: String,
    /// The table the callback is called through — the same table name
    /// the registration site named, read through an fp-array or
    /// jump-table dispatch in the partner body — e.g. `handlers`, when
    /// the chain runs through a table rather than a direct call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    /// The Rust pattern the chain suggests, e.g. one boxed closure
    /// shared between the registering and the calling function.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// Both ends' call lines — the registration line and the call
    /// line, each prefixed with its function — kept so a reviewer (or
    /// a translation prompt) can check the reasoning against both
    /// bodies.
    pub evidence: String,
}

// ============================================================
// Event systems
// ============================================================

/// One reconstructed event system across the kept bodies, with the
/// evidence behind it.
///
/// A record says the scan handed callbacks to one registration point —
/// [`registration`](Self::registration), spelled e.g.
/// `register_callback` — at two or more sites across the kept bodies,
/// the bound handlers named in [`callbacks`](Self::callbacks), while
/// at least one kept body dispatches through a table: the functions
/// named in [`dispatchers`](Self::dispatchers) each carry an fp-array
/// or jump-table reading. Many hands handing handlers to one point and
/// a table being called through — the observer shape, reconstructed
/// as a pattern inference over fragments rather than seen whole from
/// two ends like a chain, so the record reads at
/// [`confidence`](Self::confidence) 60, one rung under the chain's
/// two-ended evidence. The shape reads like
/// [`suggestion`](Self::suggestion): an observer registry of boxed
/// closures dispatched through a table. The registration lines and
/// the dispatch lines ride as [`evidence`](Self::evidence), each
/// prefixed with its function, so a reviewer (or a translation
/// prompt) can check the reconstruction against the bodies. The
/// finding attaches to the earliest registering function in listing
/// order; registrations with no visible dispatch site claim nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSystem {
    /// The function the record is about — the earliest of the
    /// registering functions in listing order.
    pub function: String,
    /// The registration point the handlers pile onto, e.g.
    /// `register_callback`.
    pub registration: String,
    /// The callbacks the registrations bound, spelled as the
    /// registration bound them, in registration order, duplicates
    /// collapsed.
    pub callbacks: Vec<String>,
    /// The functions carrying a visible dispatch site — an fp-array
    /// or jump-table reading — in listing order.
    pub dispatchers: Vec<String>,
    /// The Rust pattern the reconstruction suggests, e.g. an observer
    /// registry of boxed closures behind a dispatch table.
    pub suggestion: String,
    /// Confidence that the record is right, 0–100.
    pub confidence: Confidence,
    /// The registration and dispatch lines, each prefixed with its
    /// function and joined by a pipe — kept so a reviewer (or a
    /// translation prompt) can check the reconstruction against the
    /// bodies.
    pub evidence: String,
}

// ============================================================
// Finding union
// ============================================================

/// One callback finding, whichever detector or pass made it.
///
/// The detectors and the cross-function pass emit the concrete
/// records; the union is what the persisted result carries, so one
/// list can hold every finding for a binary and a consumer reads the
/// shared shape — function, suggestion, confidence, evidence —
/// without naming which reading produced it. Unlike typeinfer's
/// competing families, the readings read disjoint body shapes and
/// can't make competing claims for one target, so nothing is resolved
/// between variants. The serde `kind` tag names the record shape in
/// the persisted JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallbackFinding {
    /// A call through an indexed function-pointer table.
    FpArray(FpArrayCall),
    /// A call to a registration function with its callback bound.
    Registration(CallbackRegistration),
    /// A dispatch through a table of function addresses.
    JumpTable(JumpTable),
    /// A dynamic-loading plugin shape.
    Plugin(PluginArchitecture),
    /// A callback registered in one function and called in another.
    Chain(CallbackChain),
    /// Many registrations to one point plus a visible dispatch site —
    /// a reconstructed observer.
    EventSystem(EventSystem),
}

impl CallbackFinding {
    /// The function the finding is about.
    pub fn function(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.function,
            CallbackFinding::Registration(record) => &record.function,
            CallbackFinding::JumpTable(record) => &record.function,
            CallbackFinding::Plugin(record) => &record.function,
            CallbackFinding::Chain(record) => &record.function,
            CallbackFinding::EventSystem(record) => &record.function,
        }
    }

    /// The Rust dispatch pattern the finding suggests.
    pub fn suggestion(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.suggestion,
            CallbackFinding::Registration(record) => &record.suggestion,
            CallbackFinding::JumpTable(record) => &record.suggestion,
            CallbackFinding::Plugin(record) => &record.suggestion,
            CallbackFinding::Chain(record) => &record.suggestion,
            CallbackFinding::EventSystem(record) => &record.suggestion,
        }
    }

    /// Confidence that the finding is right.
    pub fn confidence(&self) -> Confidence {
        match self {
            CallbackFinding::FpArray(record) => record.confidence,
            CallbackFinding::Registration(record) => record.confidence,
            CallbackFinding::JumpTable(record) => record.confidence,
            CallbackFinding::Plugin(record) => record.confidence,
            CallbackFinding::Chain(record) => record.confidence,
            CallbackFinding::EventSystem(record) => record.confidence,
        }
    }

    /// The decompiled lines that support the finding.
    pub fn evidence(&self) -> &str {
        match self {
            CallbackFinding::FpArray(record) => &record.evidence,
            CallbackFinding::Registration(record) => &record.evidence,
            CallbackFinding::JumpTable(record) => &record.evidence,
            CallbackFinding::Plugin(record) => &record.evidence,
            CallbackFinding::Chain(record) => &record.evidence,
            CallbackFinding::EventSystem(record) => &record.evidence,
        }
    }

    /// The serde `kind` tag — `fp_array`, `registration`, `jump_table`,
    /// `plugin`, `chain`, or `event_system` — naming the reading behind
    /// the finding.
    pub fn kind(&self) -> &'static str {
        match self {
            CallbackFinding::FpArray(_) => "fp_array",
            CallbackFinding::Registration(_) => "registration",
            CallbackFinding::JumpTable(_) => "jump_table",
            CallbackFinding::Plugin(_) => "plugin",
            CallbackFinding::Chain(_) => "chain",
            CallbackFinding::EventSystem(_) => "event_system",
        }
    }

    /// What the finding names, spelled for a report row: the table the
    /// indexed call reads through, the registration call and its bound
    /// callback, the table and index of the computed dispatch, the
    /// loader pair / entry point behind the plugin shape, the callback
    /// and the partner function it reaches across, or the registration
    /// point with its handlers and the functions dispatching through a
    /// table.
    pub fn target(&self) -> String {
        match self {
            CallbackFinding::FpArray(record) => record.table.clone(),
            CallbackFinding::Registration(record) => {
                format!("{}→{}", record.registration, record.callback)
            }
            CallbackFinding::JumpTable(record) => format!("{}[{}]", record.table, record.index),
            CallbackFinding::Plugin(record) => match (&record.load, &record.resolve) {
                (Some(load), Some(resolve)) => format!("{load}→{resolve}"),
                _ => match (&record.entry_point, &record.host_table) {
                    (Some(entry), Some(table)) => format!("{entry}({table})"),
                    (Some(entry), None) => entry.clone(),
                    (None, _) => record.resolve.clone().unwrap_or_default(),
                },
            },
            CallbackFinding::Chain(record) => match &record.table {
                Some(table) if table != &record.callback => {
                    format!("{}({})→{}", record.callback, table, record.partner)
                }
                _ => format!("{}→{}", record.callback, record.partner),
            },
            CallbackFinding::EventSystem(record) => format!(
                "{}({})→{}",
                record.registration,
                record.callbacks.join(","),
                record.dispatchers.join(",")
            ),
        }
    }
}

/// Render a finding as prompt data: the function it is about, the kind
/// of pattern the detector read, the Rust callback pattern the finding
/// suggests, and the confidence and evidence behind the claim — so the
/// escalate prompt shows the hypothesis and how strongly it was made,
/// whichever detector produced it.
impl From<&CallbackFinding> for calxgloss_prompts::CallbackInfo {
    fn from(finding: &CallbackFinding) -> Self {
        Self {
            function: finding.function().to_string(),
            kind: finding.kind().to_string(),
            suggestion: finding.suggestion().to_string(),
            confidence: finding.confidence().value(),
            evidence: finding.evidence().to_string(),
        }
    }
}

// ============================================================
// Persisted result
// ============================================================

/// The callback result for one binary — the document persisted to
/// `re/analysis/callback/{dll}.json`.
///
/// The findings are the detectors' outputs in scan order: function by
/// function, and within one function the function-pointer array
/// calls, then the registrations, then the jump tables, then the
/// plugin shapes — and after every function, the cross-function
/// pass's chain findings and then its event-system findings, in
/// listing order. The readings cover disjoint shapes, so a function
/// can carry findings of every kind at
/// once and none competes with another; the stable order means two
/// scans of the same program diff cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackResult {
    /// Provenance of the scan that produced these findings.
    pub metadata: ScanMetadata,
    /// Every finding the detectors made, in scan order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<CallbackFinding>,
}

impl CallbackResult {
    /// An empty result for the binary described by `metadata`.
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            metadata,
            findings: Vec::new(),
        }
    }

    /// The findings recorded for one function, e.g. `FUN_18003ab00`.
    pub fn for_function(&self, function: &str) -> impl Iterator<Item = &CallbackFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.function() == function)
    }

    /// Whether the scan found nothing at all.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fp_array_call() -> FpArrayCall {
        FpArrayCall {
            function: "FUN_18003ab00".into(),
            table: "handlers".into(),
            suggestion: "Vec<Box<dyn Fn(...)>>".into(),
            confidence: Confidence::new(70),
            evidence: "(*(int (**)(int))handlers[uVar1])(param_1);".into(),
        }
    }

    #[test]
    fn an_fp_array_call_serde_round_trips() {
        let record = fp_array_call();
        let json = serde_json::to_string(&record).unwrap();
        // The confidence serializes as a plain number, matching the
        // workspace's serde convention.
        assert!(json.contains("\"table\":\"handlers\""));
        assert!(json.contains("\"confidence\":70"));
        let back: FpArrayCall = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn an_fp_array_record_names_the_function_the_table_and_the_pattern() {
        let json = serde_json::to_value(fp_array_call()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["table"], "handlers");
        assert_eq!(json["suggestion"], "Vec<Box<dyn Fn(...)>>");
        assert_eq!(json["confidence"], 70);
    }

    fn registration() -> CallbackRegistration {
        CallbackRegistration {
            function: "FUN_18003ab00".into(),
            registration: "register_callback".into(),
            callback: "my_handler".into(),
            suggestion: "Box<dyn Fn(...)>".into(),
            confidence: Confidence::new(70),
            evidence: "register_callback(my_handler);".into(),
        }
    }

    #[test]
    fn a_registration_serde_round_trips() {
        let record = registration();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"registration\":\"register_callback\""));
        assert!(json.contains("\"callback\":\"my_handler\""));
        let back: CallbackRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_registration_record_names_the_call_the_callback_and_the_pattern() {
        let json = serde_json::to_value(registration()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["registration"], "register_callback");
        assert_eq!(json["callback"], "my_handler");
        assert_eq!(json["suggestion"], "Box<dyn Fn(...)>");
        assert_eq!(json["confidence"], 70);
    }

    fn jump_table() -> JumpTable {
        JumpTable {
            function: "FUN_18003ab00".into(),
            table: "DAT_1400a1b60".into(),
            index: "uVar2".into(),
            target_count: Some(5),
            suggestion: "[fn(...); 5]".into(),
            confidence: Confidence::new(70),
            evidence: "if (uVar2 < 5) { (*DAT_1400a1b60[uVar2])(); }".into(),
        }
    }

    #[test]
    fn a_jump_table_serde_round_trips() {
        let record = jump_table();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"table\":\"DAT_1400a1b60\""));
        assert!(json.contains("\"index\":\"uVar2\""));
        assert!(json.contains("\"target_count\":5"));
        let back: JumpTable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_jump_table_without_a_visible_target_count_omits_it_and_reads_back_none() {
        let record = JumpTable {
            target_count: None,
            ..jump_table()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"target_count\""));
        let back: JumpTable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.target_count, None);
    }

    #[test]
    fn a_jump_table_record_names_the_table_the_index_and_the_pattern() {
        let json = serde_json::to_value(jump_table()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["table"], "DAT_1400a1b60");
        assert_eq!(json["index"], "uVar2");
        assert_eq!(json["target_count"], 5);
        assert_eq!(json["suggestion"], "[fn(...); 5]");
        assert_eq!(json["confidence"], 70);
    }

    fn plugin_architecture() -> PluginArchitecture {
        PluginArchitecture {
            function: "FUN_18003ab00".into(),
            load: Some("LoadLibrary".into()),
            resolve: Some("GetProcAddress".into()),
            entry_point: Some("Plugin_Init".into()),
            host_table: Some("host_api".into()),
            suggestion: "Box<dyn Plugin> (loader crate)".into(),
            confidence: Confidence::new(70),
            evidence: "hMod = LoadLibrary(\"plugin.dll\");".into(),
        }
    }

    #[test]
    fn a_plugin_architecture_serde_round_trips() {
        let record = plugin_architecture();
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"load\":\"LoadLibrary\""));
        assert!(json.contains("\"resolve\":\"GetProcAddress\""));
        assert!(json.contains("\"entry_point\":\"Plugin_Init\""));
        assert!(json.contains("\"host_table\":\"host_api\""));
        let back: PluginArchitecture = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn a_plugin_architecture_without_visible_partners_omits_them_and_reads_back_none() {
        // A fragment record — a lone entry-point name with no loader
        // pair and no host table — keeps the absent spellings off disk
        // and reads back as none.
        let record = PluginArchitecture {
            load: None,
            resolve: None,
            entry_point: Some("Plugin_Init".into()),
            host_table: None,
            confidence: Confidence::new(60),
            ..plugin_architecture()
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("\"load\""));
        assert!(!json.contains("\"resolve\""));
        assert!(!json.contains("\"host_table\""));
        let back: PluginArchitecture = serde_json::from_str(&json).unwrap();
        assert_eq!(back, record);
        assert_eq!(back.load, None);
        assert_eq!(back.host_table, None);
    }

    #[test]
    fn a_plugin_architecture_record_names_the_loader_pair_the_entry_point_and_the_pattern() {
        let json = serde_json::to_value(plugin_architecture()).unwrap();
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["load"], "LoadLibrary");
        assert_eq!(json["resolve"], "GetProcAddress");
        assert_eq!(json["entry_point"], "Plugin_Init");
        assert_eq!(json["host_table"], "host_api");
        assert_eq!(json["suggestion"], "Box<dyn Plugin> (loader crate)");
        assert_eq!(json["confidence"], 70);
    }

    fn chain() -> CallbackChain {
        CallbackChain {
            function: "FUN_18003ab00".into(),
            partner: "FUN_18003e750".into(),
            callback: "my_handler".into(),
            table: Some("handlers".into()),
            suggestion: "Box<dyn Fn(...)> shared between the registering and calling functions"
                .into(),
            confidence: Confidence::new(70),
            evidence: "FUN_18003ab00: register_callback(handlers); FUN_18003e750: \
                       (*(int (**)(int))handlers[uVar1])(param_1);"
                .into(),
        }
    }

    #[test]
    fn a_chain_serde_round_trips() {
        let record = chain();
        let json = serde_json::to_string(&record).expect("chain record should serialize");
        assert!(json.contains("\"partner\":\"FUN_18003e750\""));
        assert!(json.contains("\"callback\":\"my_handler\""));
        assert!(json.contains("\"table\":\"handlers\""));
        let back: CallbackChain =
            serde_json::from_str(&json).expect("chain document should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn a_chain_without_a_table_omits_it_and_reads_back_none() {
        // A direct-name chain — the callback itself called in the
        // partner body — keeps the absent table off disk and reads
        // back as none.
        let record = CallbackChain {
            table: None,
            ..chain()
        };
        let json = serde_json::to_string(&record).expect("table-less chain should serialize");
        assert!(!json.contains("\"table\""));
        let back: CallbackChain =
            serde_json::from_str(&json).expect("table-less chain should read back");
        assert_eq!(back, record);
        assert_eq!(back.table, None);
    }

    #[test]
    fn a_chain_record_names_both_functions_the_callback_and_the_table() {
        let json = serde_json::to_value(chain()).expect("chain record should serialize");
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["partner"], "FUN_18003e750");
        assert_eq!(json["callback"], "my_handler");
        assert_eq!(json["table"], "handlers");
        assert_eq!(
            json["suggestion"],
            "Box<dyn Fn(...)> shared between the registering and calling functions"
        );
        assert_eq!(json["confidence"], 70);
    }

    fn event_system() -> EventSystem {
        EventSystem {
            function: "FUN_18003ab00".into(),
            registration: "register_callback".into(),
            callbacks: vec!["handler_a".into(), "handler_b".into()],
            dispatchers: vec!["FUN_18003e750".into()],
            suggestion: "Observer pattern: registered Box<dyn Fn(...)> handlers dispatched \
                         through a table"
                .into(),
            confidence: Confidence::new(60),
            evidence: "FUN_18003ab00: register_callback(handler_a); | \
                       FUN_18003ab00: register_callback(handler_b); | \
                       FUN_18003e750: handlers[uVar1](param_1);"
                .into(),
        }
    }

    #[test]
    fn an_event_system_serde_round_trips() {
        let record = event_system();
        let json = serde_json::to_string(&record).expect("event system record should serialize");
        assert!(json.contains("\"registration\":\"register_callback\""));
        assert!(json.contains("\"callbacks\":[\"handler_a\",\"handler_b\"]"));
        assert!(json.contains("\"dispatchers\":[\"FUN_18003e750\"]"));
        let back: EventSystem =
            serde_json::from_str(&json).expect("event system record should read back");
        assert_eq!(back, record);
    }

    #[test]
    fn an_event_system_record_names_the_registration_the_callbacks_and_the_dispatchers() {
        let json =
            serde_json::to_value(event_system()).expect("event system record should serialize");
        assert_eq!(json["function"], "FUN_18003ab00");
        assert_eq!(json["registration"], "register_callback");
        assert_eq!(json["callbacks"][0], "handler_a");
        assert_eq!(json["callbacks"][1], "handler_b");
        assert_eq!(json["dispatchers"][0], "FUN_18003e750");
        assert_eq!(
            json["suggestion"],
            "Observer pattern: registered Box<dyn Fn(...)> handlers dispatched through a table"
        );
        assert_eq!(json["confidence"], 60);
    }

    #[test]
    fn an_fp_array_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::FpArray(fp_array_call());
        let json = serde_json::to_string(&finding).expect("fp array finding should serialize");
        // The union is internally tagged: the kind names the record
        // shape and the payload's own fields sit beside it.
        assert!(json.contains("\"kind\":\"fp_array\""));
        assert!(json.contains("\"table\":\"handlers\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("fp array finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_registration_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::Registration(registration());
        let json = serde_json::to_string(&finding).expect("registration finding should serialize");
        assert!(json.contains("\"kind\":\"registration\""));
        assert!(json.contains("\"registration\":\"register_callback\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("registration finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_jump_table_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::JumpTable(jump_table());
        let json = serde_json::to_string(&finding).expect("jump table finding should serialize");
        assert!(json.contains("\"kind\":\"jump_table\""));
        assert!(json.contains("\"index\":\"uVar2\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("jump table finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_plugin_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::Plugin(plugin_architecture());
        let json = serde_json::to_string(&finding).expect("plugin finding should serialize");
        assert!(json.contains("\"kind\":\"plugin\""));
        assert!(json.contains("\"resolve\":\"GetProcAddress\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("plugin finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn a_chain_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::Chain(chain());
        let json = serde_json::to_string(&finding).expect("chain finding should serialize");
        assert!(json.contains("\"kind\":\"chain\""));
        assert!(json.contains("\"partner\":\"FUN_18003e750\""));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("chain finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn an_event_system_finding_serde_round_trips_under_its_kind_tag() {
        let finding = CallbackFinding::EventSystem(event_system());
        let json = serde_json::to_string(&finding).expect("event system finding should serialize");
        assert!(json.contains("\"kind\":\"event_system\""));
        assert!(json.contains("\"dispatchers\":[\"FUN_18003e750\"]"));
        let back: CallbackFinding =
            serde_json::from_str(&json).expect("event system finding should read back");
        assert_eq!(back, finding);
    }

    #[test]
    fn the_union_accessors_reach_through_every_variant() {
        let findings = [
            CallbackFinding::FpArray(fp_array_call()),
            CallbackFinding::Registration(registration()),
            CallbackFinding::JumpTable(jump_table()),
            CallbackFinding::Plugin(plugin_architecture()),
            CallbackFinding::Chain(chain()),
            CallbackFinding::EventSystem(event_system()),
        ];
        for finding in &findings {
            assert_eq!(finding.function(), "FUN_18003ab00");
            assert!(!finding.suggestion().is_empty());
            assert!(!finding.evidence().is_empty());
        }
        let kinds: Vec<&str> = findings.iter().map(|f| f.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                "fp_array",
                "registration",
                "jump_table",
                "plugin",
                "chain",
                "event_system",
            ]
        );
        let confidences: Vec<u8> = findings.iter().map(|f| f.confidence().value()).collect();
        assert_eq!(confidences, vec![70, 70, 70, 70, 70, 60]);
        let suggestions: Vec<&str> = findings.iter().map(|f| f.suggestion()).collect();
        assert_eq!(
            suggestions,
            vec![
                "Vec<Box<dyn Fn(...)>>",
                "Box<dyn Fn(...)>",
                "[fn(...); 5]",
                "Box<dyn Plugin> (loader crate)",
                "Box<dyn Fn(...)> shared between the registering and calling functions",
                "Observer pattern: registered Box<dyn Fn(...)> handlers dispatched through a table",
            ]
        );
        let targets: Vec<String> = findings.iter().map(|f| f.target()).collect();
        assert_eq!(
            targets,
            vec![
                "handlers",
                "register_callback→my_handler",
                "DAT_1400a1b60[uVar2]",
                "LoadLibrary→GetProcAddress",
                "my_handler(handlers)→FUN_18003e750",
                "register_callback(handler_a,handler_b)→FUN_18003e750",
            ]
        );
    }

    #[test]
    fn a_chain_finding_target_names_its_visible_shape() {
        // The report row names the callback and the partner it reaches
        // across; a table the chain runs through shows when it is not
        // just the callback's own spelling.
        let direct = CallbackFinding::Chain(CallbackChain {
            table: None,
            ..chain()
        });
        assert_eq!(direct.target(), "my_handler→FUN_18003e750");

        let through_table = CallbackFinding::Chain(CallbackChain {
            callback: "handlers".into(),
            ..chain()
        });
        assert_eq!(through_table.target(), "handlers→FUN_18003e750");

        let named_table = CallbackFinding::Chain(CallbackChain {
            callback: "my_handler".into(),
            table: Some("handlers".into()),
            ..chain()
        });
        assert_eq!(named_table.target(), "my_handler(handlers)→FUN_18003e750");
    }

    #[test]
    fn a_plugin_finding_target_names_its_visible_shape() {
        // The report row names what the record actually saw: the loader
        // pair for a full shape, the entry point and its host table for
        // a fragment, the lone resolve when that is all there is.
        let full = CallbackFinding::Plugin(plugin_architecture());
        assert_eq!(full.target(), "LoadLibrary→GetProcAddress");

        let entry_fragment = CallbackFinding::Plugin(PluginArchitecture {
            load: None,
            resolve: None,
            entry_point: Some("GetPluginInfo".into()),
            host_table: Some("host_api".into()),
            confidence: Confidence::new(60),
            ..plugin_architecture()
        });
        assert_eq!(entry_fragment.target(), "GetPluginInfo(host_api)");

        let resolve_fragment = CallbackFinding::Plugin(PluginArchitecture {
            load: None,
            resolve: Some("dlsym".into()),
            entry_point: None,
            host_table: None,
            confidence: Confidence::new(60),
            ..plugin_architecture()
        });
        assert_eq!(resolve_fragment.target(), "dlsym");
    }

    #[test]
    fn every_finding_variant_renders_as_prompt_data() {
        let fp_array = CallbackFinding::FpArray(fp_array_call());
        let info = calxgloss_prompts::CallbackInfo::from(&fp_array);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "fp_array");
        assert_eq!(info.suggestion, "Vec<Box<dyn Fn(...)>>");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.evidence, "(*(int (**)(int))handlers[uVar1])(param_1);");

        let registration = CallbackFinding::Registration(registration());
        let info = calxgloss_prompts::CallbackInfo::from(&registration);
        assert_eq!(info.kind, "registration");
        assert_eq!(info.suggestion, "Box<dyn Fn(...)>");

        let jump_table = CallbackFinding::JumpTable(jump_table());
        let info = calxgloss_prompts::CallbackInfo::from(&jump_table);
        assert_eq!(info.kind, "jump_table");
        assert_eq!(info.suggestion, "[fn(...); 5]");

        let plugin = CallbackFinding::Plugin(plugin_architecture());
        let info = calxgloss_prompts::CallbackInfo::from(&plugin);
        assert_eq!(info.kind, "plugin");
        assert_eq!(info.suggestion, "Box<dyn Plugin> (loader crate)");
        assert_eq!(info.confidence, 70);
        assert_eq!(info.evidence, "hMod = LoadLibrary(\"plugin.dll\");");

        let chain = CallbackFinding::Chain(chain());
        let info = calxgloss_prompts::CallbackInfo::from(&chain);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "chain");
        assert_eq!(
            info.suggestion,
            "Box<dyn Fn(...)> shared between the registering and calling functions"
        );
        assert_eq!(info.confidence, 70);
        assert!(info.evidence.contains("register_callback(handlers);"));

        let event_system = CallbackFinding::EventSystem(event_system());
        let info = calxgloss_prompts::CallbackInfo::from(&event_system);
        assert_eq!(info.function, "FUN_18003ab00");
        assert_eq!(info.kind, "event_system");
        assert_eq!(
            info.suggestion,
            "Observer pattern: registered Box<dyn Fn(...)> handlers dispatched through a table"
        );
        assert_eq!(info.confidence, 60);
        assert!(info.evidence.contains("register_callback(handler_b);"));
        assert!(info.evidence.contains("handlers[uVar1](param_1);"));
    }

    #[test]
    fn a_callback_result_serde_round_trips() {
        let result = CallbackResult {
            metadata: ScanMetadata {
                binary: "eqmain.dll".into(),
                scanned_at: 1_759_488_000,
                duration_secs: 12,
                engine: None,
            },
            findings: vec![
                CallbackFinding::FpArray(fp_array_call()),
                CallbackFinding::Registration(registration()),
                CallbackFinding::JumpTable(jump_table()),
                CallbackFinding::Plugin(plugin_architecture()),
                CallbackFinding::Chain(chain()),
            ],
        };
        let json = serde_json::to_string(&result).expect("callback result should serialize");
        let back: CallbackResult =
            serde_json::from_str(&json).expect("callback result should read back");
        assert_eq!(back, result);
    }

    #[test]
    fn a_result_without_findings_omits_them_and_reads_back_empty() {
        // Documents persisted before a finding landed still load, and an
        // empty scan stays small on disk.
        let result = CallbackResult::new(ScanMetadata::new("eqmain.dll"));
        let json = serde_json::to_string(&result).expect("empty callback result should serialize");
        assert!(!json.contains("\"findings\""));
        let back: CallbackResult =
            serde_json::from_str(&json).expect("empty callback result should read back");
        assert!(back.is_empty());
        assert_eq!(back.metadata.binary, "eqmain.dll");
    }

    #[test]
    fn for_function_yields_only_that_function_s_findings_in_order() {
        let other = CallbackFinding::FpArray(FpArrayCall {
            function: "FUN_18003e750".into(),
            table: "callbacks".into(),
            suggestion: "Vec<Box<dyn Fn(...)>>".into(),
            confidence: Confidence::new(70),
            evidence: "callbacks[uVar3](param_2);".into(),
        });
        let result = CallbackResult {
            metadata: ScanMetadata::new("eqmain.dll"),
            findings: vec![other.clone(), CallbackFinding::Registration(registration())],
        };
        let found: Vec<&CallbackFinding> = result.for_function("FUN_18003e750").collect();
        assert_eq!(found, vec![&other]);
        assert!(result.for_function("FUN_180099999").next().is_none());
        assert!(!result.is_empty());
    }
}
