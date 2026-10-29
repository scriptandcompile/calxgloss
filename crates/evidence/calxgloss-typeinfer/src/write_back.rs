//! Writing the surviving inferences back into the loaded program.
//!
//! The scan's records are hypotheses persisted to JSON; this module is where
//! a deliberate operator run turns selected ones into program facts through
//! the [`TypeWriteSource`] seam (ADR-0020). [`WriteBack`] drives the pass in
//! the order the program needs: create the named types the records reference
//! first, so no write names a type the engine cannot resolve; then function
//! prototypes, merging the inferred parameter and return readings into each
//! function's *existing* prototype text; then local-variable types.
//!
//! The pass is conservative by construction:
//!
//! - A confidence floor gates which records apply at all; everything below
//!   it is skipped with the reason recorded.
//! - A slot the engine already types concretely is never overwritten — only the
//!   `undefined` family (`undefined`, `undefined1`..`undefined8`, and their
//!   pointer spellings) is narrowed.
//! - A missing named type becomes a one-byte typedef placeholder
//!   (`create_typedef(name, "undefined")`), never a fabricated layout: the
//!   bridge refuses a fieldless `create_struct`, and a 1-byte placeholder is
//!   exactly what the bridge's `replace_placeholder` flow lets later layout
//!   work replace. An existing name is never recreated — `create_typedef`
//!   silently replaces, which would clobber a real struct.
//! - One failed write never aborts the pass: every failure is collected and
//!   the run ends with an applied / skipped / failed report.
//!
//! The record's own type text is normalized only at this seam: the persisted
//! `u32`/`u64` spellings the detectors emit are not what the engine's C parser
//! resolves, so the write carries the built-in spellings instead.

use std::collections::{HashMap, HashSet};

use calxgloss_decomp::{ScanSource, TypeWriteSource};
use tracing::{info, warn};

use crate::error::Result;
use crate::types::{Confidence, InferredType, TypeInferenceResult};

/// The base type a placeholder typedef aliases — the engine's smallest concrete
/// type, so the placeholder is 1 byte and the bridge's `replace_placeholder`
/// flow can swap in a real layout later.
const PLACEHOLDER_BASE: &str = "undefined";

/// Type names the engine's own resolver already answers for — a record naming
/// one of these needs no type created for it.
const ENGINE_BASE_TYPES: &[&str] = &[
    "void",
    "char",
    "uchar",
    "short",
    "ushort",
    "int",
    "uint",
    "long",
    "ulong",
    "longlong",
    "ulonglong",
    "float",
    "double",
    "bool",
    "boolean",
    "byte",
    "sbyte",
    "word",
    "dword",
    "qword",
    "wchar_t",
    "wchar16",
    "wchar32",
    "size_t",
    "ssize_t",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined3",
    "undefined4",
    "undefined5",
    "undefined6",
    "undefined7",
    "undefined8",
];

// ============================================================
// The report
// ============================================================

/// Why one record was not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The record's confidence is under the floor the run was given.
    BelowFloor { confidence: u8, floor: u8 },
    /// the engine already types the slot concretely — only undefined slots are
    /// narrowed, so a hand-typed slot survives the pass.
    ConcreteSlot,
    /// The record's function is not in the loaded program's listing.
    FunctionNotFound,
    /// The slot the record names is not in the function's current signature
    /// or decompiled body.
    SlotNotFound,
    /// A call-site record types an argument at a call site, not a program
    /// slot — the parameter and local record kinds carry what a slot gets.
    CallSiteArgument,
    /// A convention record says how a function is called, not a type the
    /// program can hold in a slot — the setters speak types.
    Convention,
    /// A direction record says which way data flows through a parameter,
    /// not a type the program can hold in a slot — direction never
    /// writes back (issue #274).
    Direction,
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BelowFloor { confidence, floor } => {
                write!(f, "confidence {confidence} below floor {floor}")
            }
            Self::ConcreteSlot => write!(f, "The engine already types it concretely"),
            Self::FunctionNotFound => write!(f, "function not in the program"),
            Self::SlotNotFound => write!(f, "slot not in the current body"),
            Self::CallSiteArgument => write!(f, "call-site reading, not a program slot"),
            Self::Convention => write!(f, "not a program type"),
            Self::Direction => write!(f, "direction reading, not a program type"),
        }
    }
}

/// One record the pass did not apply, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRecord {
    /// The record's target, e.g. `FUN_18003ab00 param_1`.
    pub target: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// One write the pass attempted and the program refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedRecord {
    /// What the write was for, e.g. `FUN_18003ab00 prototype` or `type Widget`.
    pub target: String,
    /// The error the write raised.
    pub error: String,
}

/// The outcome of one write-back pass — the applied / skipped / failed
/// accounting the run reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBackReport {
    /// Named types created before any record that references them applied.
    pub types_created: usize,
    /// Records whose write landed.
    pub applied: usize,
    /// Records not applied, each with its reason.
    pub skipped: Vec<SkippedRecord>,
    /// Writes attempted and refused, each with its error.
    pub failed: Vec<FailedRecord>,
}

// ============================================================
// The driver
// ============================================================

/// The write-back pass, generic over both engine seams: `S` answers the
/// reads the pass needs (the function listing for addresses, the current
/// prototypes and bodies, the Type Manager's names) and `W` carries the
/// writes. The CLI hands both the loaded [`calxgloss_kuna::KunaSource`]
/// — the read cache never implements the write trait (ADR-0020) — and tests
/// hand a canned program and a recording writer.
#[derive(Debug)]
pub struct WriteBack<'a, S, W> {
    source: &'a S,
    writer: &'a W,
    floor: Confidence,
}

impl<'a, S: ScanSource, W: TypeWriteSource> WriteBack<'a, S, W> {
    /// A pass reading through `source`, writing through `writer`, and
    /// applying only records at `floor` confidence or above.
    pub fn new(source: &'a S, writer: &'a W, floor: Confidence) -> Self {
        Self {
            source,
            writer,
            floor,
        }
    }

    /// Apply `result`'s surviving inferences to the loaded program.
    ///
    /// The order is fixed: create missing named types → set function
    /// prototypes → set local-variable types. Only the setup reads — the
    /// function listing and the Type Manager listing — can fail the run;
    /// every per-function read and every write that fails is collected into
    /// the report and the pass continues.
    pub async fn apply(&self, result: &TypeInferenceResult) -> Result<WriteBackReport> {
        let mut report = WriteBackReport::default();

        // Floor gate first, and the records that type no program slot —
        // call-site readings, convention readings, and direction
        // readings — aside: the setters hold types in parameters and
        // locals, not arguments at a site, a calling convention, or a
        // direction.
        let mut surviving: Vec<&InferredType> = Vec::new();
        for record in &result.inferences {
            if record.confidence() < self.floor {
                report.skipped.push(SkippedRecord {
                    target: target_of(record),
                    reason: SkipReason::BelowFloor {
                        confidence: record.confidence().value(),
                        floor: self.floor.value(),
                    },
                });
            } else if matches!(record, InferredType::CallSite(_)) {
                report.skipped.push(SkippedRecord {
                    target: target_of(record),
                    reason: SkipReason::CallSiteArgument,
                });
            } else if matches!(record, InferredType::Convention(_)) {
                report.skipped.push(SkippedRecord {
                    target: target_of(record),
                    reason: SkipReason::Convention,
                });
            } else if matches!(record, InferredType::Direction(_)) {
                report.skipped.push(SkippedRecord {
                    target: target_of(record),
                    reason: SkipReason::Direction,
                });
            } else {
                surviving.push(record);
            }
        }
        if surviving.is_empty() {
            return Ok(report);
        }

        // Both setters address the function by address (ADR-0020), and the
        // missing-type check needs the Type Manager's current names.
        let addresses: HashMap<String, u64> = self
            .source
            .functions()
            .await?
            .into_iter()
            .map(|function| (function.name, function.address))
            .collect();
        let existing_types: HashSet<String> = self
            .source
            .data_types(None)
            .await?
            .into_iter()
            .map(|entry| entry.name)
            .collect();

        // Group by function in first-appearance order, and drop the records
        // whose function the program does not hold.
        let mut groups: Vec<(&str, u64, Vec<&InferredType>)> = Vec::new();
        for record in &surviving {
            let function = record.function();
            let Some(&address) = addresses.get(function) else {
                report.skipped.push(SkippedRecord {
                    target: target_of(record),
                    reason: SkipReason::FunctionNotFound,
                });
                continue;
            };
            match groups.iter_mut().find(|(name, _, _)| *name == function) {
                Some((_, _, records)) => records.push(record),
                None => groups.push((function, address, vec![record])),
            }
        }

        // Phase 1 — the named types the surviving records reference, created
        // before anything applies them. Only records whose function the
        // program actually holds count: a record already skipped as
        // function-not-found must not seed the Type Manager with a type
        // nothing will ever apply. Deduped, first-seen order; existing
        // names are never recreated.
        let mut created: HashSet<String> = HashSet::new();
        for (_, _, records) in &groups {
            for record in records {
                let Some(name) = named_type_needed(record.inferred_type()) else {
                    continue;
                };
                if existing_types.contains(name) || !created.insert(name.to_string()) {
                    continue;
                }
                match self.writer.create_typedef(name, PLACEHOLDER_BASE).await {
                    Ok(()) => report.types_created += 1,
                    Err(error) => report.failed.push(FailedRecord {
                        target: format!("type {name}"),
                        error: error.to_string(),
                    }),
                }
            }
        }

        // Bodies fetched for the prototype pass are reused by the locals
        // pass — one decompile per function per run.
        let mut bodies: HashMap<String, calxgloss_decomp::DecompiledFunction> = HashMap::new();

        // Phase 2 — function prototypes: merge the inferred parameter and
        // return readings into each function's existing prototype text.
        for (function, address, records) in &groups {
            let typed = records
                .iter()
                .filter(|record| matches!(record, InferredType::Param(_) | InferredType::Return(_)))
                .collect::<Vec<_>>();
            if typed.is_empty() {
                continue;
            }

            let body = match self.body(function, &mut bodies).await {
                Ok(body) => body,
                Err(error) => {
                    for record in typed {
                        report.failed.push(FailedRecord {
                            target: target_of(record),
                            error: error.to_string(),
                        });
                    }
                    continue;
                }
            };
            let Some(signature) = ParsedSignature::parse(&body.signature) else {
                for record in typed {
                    report.failed.push(FailedRecord {
                        target: target_of(record),
                        error: format!(
                            "could not parse the current prototype {:?}",
                            body.signature
                        ),
                    });
                }
                continue;
            };

            let mut parameters = signature.parameters.clone();
            let mut return_type = signature.return_type.clone();
            let mut merged: Vec<String> = Vec::new();
            for record in typed {
                match *record {
                    InferredType::Param(record) => match parameters.get_mut(record.param_index) {
                        None => report.skipped.push(SkippedRecord {
                            target: param_target(record),
                            reason: SkipReason::SlotNotFound,
                        }),
                        Some(parameter) if !is_undefined_type(&parameter.type_text) => {
                            report.skipped.push(SkippedRecord {
                                target: param_target(record),
                                reason: SkipReason::ConcreteSlot,
                            });
                        }
                        Some(parameter) => {
                            parameter.type_text =
                                engine_type_text(&record.inferred_type).to_string();
                            merged.push(param_target(record));
                        }
                    },
                    InferredType::Return(record) => {
                        let target = format!("{} return", record.function);
                        if !is_undefined_type(&return_type) {
                            report.skipped.push(SkippedRecord {
                                target,
                                reason: SkipReason::ConcreteSlot,
                            });
                        } else {
                            return_type = engine_type_text(&record.inferred_type).to_string();
                            merged.push(target);
                        }
                    }
                    _ => {}
                }
            }
            if merged.is_empty() {
                continue;
            }

            let prototype = signature.reassemble(&return_type, &parameters);
            match self
                .writer
                .set_function_prototype(*address, &prototype)
                .await
            {
                Ok(()) => report.applied += merged.len(),
                Err(error) => {
                    for target in merged {
                        report.failed.push(FailedRecord {
                            target,
                            error: error.to_string(),
                        });
                    }
                }
            }
        }

        // Phase 3 — local-variable types, read against the same bodies.
        for (function, address, records) in &groups {
            let locals: Vec<_> = records
                .iter()
                .filter(|record| matches!(record, InferredType::Local(_)))
                .collect();
            if locals.is_empty() {
                continue;
            }

            let body = match self.body(function, &mut bodies).await {
                Ok(body) => body,
                Err(error) => {
                    for record in &locals {
                        report.failed.push(FailedRecord {
                            target: target_of(record),
                            error: error.to_string(),
                        });
                    }
                    continue;
                }
            };
            let declared = declared_locals(&body.body);
            for record in &locals {
                let InferredType::Local(record) = **record else {
                    continue;
                };
                match declared.get(&record.variable_name) {
                    None => report.skipped.push(SkippedRecord {
                        target: local_target(record),
                        reason: SkipReason::SlotNotFound,
                    }),
                    Some(type_text) if !is_undefined_type(type_text) => {
                        report.skipped.push(SkippedRecord {
                            target: local_target(record),
                            reason: SkipReason::ConcreteSlot,
                        });
                    }
                    Some(_) => {
                        let new_type = engine_type_text(&record.inferred_type);
                        match self
                            .writer
                            .set_local_variable_type(*address, &record.variable_name, new_type)
                            .await
                        {
                            Ok(()) => report.applied += 1,
                            Err(error) => report.failed.push(FailedRecord {
                                target: local_target(record),
                                error: error.to_string(),
                            }),
                        }
                    }
                }
            }
        }

        info!(
            applied = report.applied,
            types_created = report.types_created,
            skipped = report.skipped.len(),
            failed = report.failed.len(),
            floor = self.floor.value(),
            "Type write-back pass finished"
        );
        for failure in &report.failed {
            warn!(target = %failure.target, error = %failure.error, "write-back write refused");
        }
        Ok(report)
    }

    /// The function's decompiled body, fetched at most once per run.
    async fn body(
        &self,
        function: &str,
        bodies: &mut HashMap<String, calxgloss_decomp::DecompiledFunction>,
    ) -> Result<calxgloss_decomp::DecompiledFunction> {
        if let Some(body) = bodies.get(function) {
            return Ok(body.clone());
        }
        let fetched = self.source.decompile(function).await?;
        bodies.insert(function.to_string(), fetched.clone());
        Ok(fetched)
    }
}

// ============================================================
// Type-text rules
// ============================================================

/// The named type a record's type text references and the engine may not hold
/// yet — the base of a pointer or a by-value named type, when it is a plain
/// identifier and not one of the engine's own base types. Qualified spellings
/// (`Namespace::Type`) name no creatable single type through this seam, and
/// multi-word C spellings (`unsigned int`) resolve on their own.
fn named_type_needed(type_text: &str) -> Option<&str> {
    // Normalize the Rust-flavored widths first: `u32` is the detector's
    // spelling of the engine's own `uint`, not a name to create.
    let base = engine_type_text(type_text)
        .trim()
        .trim_end_matches('*')
        .trim();
    let is_identifier = !base.is_empty()
        && (base.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        && base
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if is_identifier && !ENGINE_BASE_TYPES.contains(&base.to_ascii_lowercase().as_str()) {
        Some(base)
    } else {
        None
    }
}

/// The engine-resolvable spelling of a record's type text. The detectors
/// persist Rust-flavored widths (`u32`, `u64`) for the prompts; the engine's
/// C parser resolves the built-in spellings instead. Everything else passes
/// through unchanged.
fn engine_type_text(type_text: &str) -> &str {
    match type_text {
        "u8" => "uchar",
        "u16" => "ushort",
        "u32" => "uint",
        "u64" => "ulonglong",
        other => other,
    }
}

/// Whether a current slot type is still the decompiler's placeholder — the
/// only slots write-back narrows. `void` is a decision, not a placeholder,
/// and a pointer to the placeholder (`undefined *`) is still untyped.
fn is_undefined_type(type_text: &str) -> bool {
    let base = type_text
        .trim()
        .trim_end_matches('*')
        .trim()
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "undefined"
            | "undefined1"
            | "undefined2"
            | "undefined3"
            | "undefined4"
            | "undefined5"
            | "undefined6"
            | "undefined7"
            | "undefined8"
    )
}

/// The report name of a record's target: the function plus what it types —
/// a parameter's decompiled name (or position), a local's name, `return`,
/// `convention`, a parameter carrying a direction reading, or the call
/// site a call-site record read.
fn target_of(record: &InferredType) -> String {
    let subject = match record {
        InferredType::Param(record) => return param_target(record),
        InferredType::Local(record) => return local_target(record),
        InferredType::CallSite(record) => match record.arg_name.as_deref() {
            Some(arg) => format!("{}({arg})", record.callee),
            None => format!("{} arg {}", record.callee, record.arg_index + 1),
        },
        InferredType::Return(_) => "return".to_string(),
        InferredType::Convention(_) => "convention".to_string(),
        // A function can carry several direction readings, so the name
        // says which parameter's direction was skipped.
        InferredType::Direction(record) => {
            let param = record
                .param_name
                .clone()
                .unwrap_or_else(|| format!("param_{}", record.param_index + 1));
            format!("{param} direction")
        }
    };
    format!("{} {subject}", record.function())
}

/// The report name a parameter record points at.
fn param_target(record: &crate::types::InferredParamType) -> String {
    let subject = record
        .param_name
        .clone()
        .unwrap_or_else(|| format!("param_{}", record.param_index + 1));
    format!("{} {subject}", record.function)
}

/// The report name a local-variable record points at.
fn local_target(record: &crate::types::InferredLocalType) -> String {
    format!("{} {}", record.function, record.variable_name)
}

// ============================================================
// Current-prototype reading
// ============================================================

/// One parameter of a decompiled signature: its current type text and name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedParameter {
    type_text: String,
    name: String,
}

/// A decompiled signature line split into the parts write-back merges into:
/// the current return type, any calling-convention spelling between the type
/// and the name, the function name, and the parameters. The name and every
/// untouched slot come back out verbatim, so a merge changes only the slots
/// it narrows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSignature {
    return_type: String,
    convention: Vec<String>,
    name: String,
    parameters: Vec<ParsedParameter>,
    varargs: bool,
}

impl ParsedSignature {
    /// Split `ret name(type name, ...)` — the decompiler's signature line —
    /// or nothing when the line is not shaped like one.
    fn parse(signature: &str) -> Option<Self> {
        let open = signature.find('(')?;
        let close = signature.rfind(')')?;
        if close < open {
            return None;
        }

        // The name is the last identifier before the parameter list, so a
        // return type carrying parentheses cannot steal it; convention
        // spellings (`__thiscall` and friends) sit between type and name.
        let head = signature[..open].trim();
        let tokens: Vec<&str> = head.split_whitespace().collect();
        let name = (*tokens.last()?).to_string();
        let convention: Vec<String> = tokens[..tokens.len() - 1]
            .iter()
            .filter(|token| token.starts_with("__"))
            .map(|token| token.to_string())
            .collect();
        let return_type = tokens[..tokens.len() - 1]
            .iter()
            .filter(|token| !token.starts_with("__"))
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        if name.is_empty() {
            return None;
        }

        let body = signature[open + 1..close].trim();
        let mut parameters = Vec::new();
        let mut varargs = false;
        for text in body.split(',') {
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            if text == "..." {
                varargs = true;
                continue;
            }
            // `void` alone is the decompiler's empty parameter list.
            if body == "void" {
                continue;
            }
            let (type_text, name) = split_declarator(text);
            if type_text.is_empty() || name.is_empty() {
                return None;
            }
            parameters.push(ParsedParameter {
                type_text: type_text.to_string(),
                name: name.to_string(),
            });
        }

        Some(Self {
            return_type,
            convention,
            name,
            parameters,
            varargs,
        })
    }

    /// Rebuild the prototype text with the (possibly narrowed) return type
    /// and parameters; everything the pass did not narrow comes back out as
    /// it came in.
    fn reassemble(&self, return_type: &str, parameters: &[ParsedParameter]) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !return_type.is_empty() {
            parts.push(return_type.to_string());
        }
        parts.extend(self.convention.iter().cloned());
        parts.push(self.name.clone());
        let mut parameter_text: Vec<String> = parameters
            .iter()
            .map(|parameter| format!("{} {}", parameter.type_text, parameter.name))
            .collect();
        if self.varargs {
            parameter_text.push("...".to_string());
        }
        format!("{}({})", parts.join(" "), parameter_text.join(", "))
    }
}

/// Split a `type name` declarator at its trailing identifier — `char *param_1`
/// is type `char *`, name `param_1`.
fn split_declarator(text: &str) -> (&str, &str) {
    let text = text.trim();
    let mut end = text.len();
    while end > 0 {
        let byte = text.as_bytes()[end - 1];
        if byte.is_ascii_alphanumeric() || byte == b'_' {
            end -= 1;
        } else {
            break;
        }
    }
    (text[..end].trim(), text[end..].trim())
}

/// The variables a decompiled body declares, name → declared type. Only
/// plain declaration lines count — `undefined8 local_8;` — so assignments,
/// calls, and array slots never read as a narrowable declaration.
fn declared_locals(body: &str) -> HashMap<String, String> {
    const STATEMENT_KEYWORDS: &[&str] = &[
        "return", "if", "for", "while", "switch", "do", "else", "break", "continue", "goto",
        "case", "default",
    ];
    let mut declared = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        let Some(declarator) = line.strip_suffix(';') else {
            continue;
        };
        if declarator.contains('(')
            || declarator.contains('=')
            || declarator.contains('[')
            || declarator.is_empty()
        {
            continue;
        }
        let (type_text, name) = split_declarator(declarator);
        if type_text.is_empty()
            || name.is_empty()
            || STATEMENT_KEYWORDS.contains(&type_text)
            || !type_text.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            continue;
        }
        declared.insert(name.to_string(), type_text.to_string());
    }
    declared
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, NewStructField,
        StringLiteral, StructLayout, Symbol, Xref,
    };

    use super::*;
    use crate::types::{
        CallingConvention, Direction, InferredCallType, InferredConvention, InferredLocalType,
        InferredParamDirection, InferredParamType, InferredReturnType, ScanMetadata,
    };

    // ------------------------------------------------------------
    // A canned program answering the pass's reads
    // ------------------------------------------------------------

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    #[derive(Default)]
    struct FakeProgram {
        listing: Vec<(String, u64)>,
        bodies: HashMap<String, DecompiledFunction>,
        type_names: Vec<String>,
    }

    impl FakeProgram {
        fn new() -> Self {
            Self::default()
        }

        fn with_function(mut self, address: u64, name: &str, signature: &str, body: &str) -> Self {
            self.listing.push((name.to_string(), address));
            self.bodies
                .insert(name.to_string(), function(name, signature, body));
            self
        }

        fn with_types(mut self, names: &[&str]) -> Self {
            self.type_names
                .extend(names.iter().map(|name| name.to_string()));
            self
        }
    }

    impl ScanSource for FakeProgram {
        async fn functions(
            &self,
        ) -> calxgloss_decomp::Result<Vec<calxgloss_decomp::FunctionSummary>> {
            Ok(self
                .listing
                .iter()
                .map(|(name, address)| calxgloss_decomp::FunctionSummary {
                    name: name.clone(),
                    address: *address,
                })
                .collect())
        }
        async fn decompile(&self, name: &str) -> calxgloss_decomp::Result<DecompiledFunction> {
            self.bodies.get(name).cloned().ok_or(EngineError::NotFound {
                kind: "function",
                query: name.to_string(),
            })
        }
        async fn data_types(
            &self,
            _category: Option<&str>,
        ) -> calxgloss_decomp::Result<Vec<DataTypeEntry>> {
            Ok(self
                .type_names
                .iter()
                .map(|name| DataTypeEntry {
                    name: name.clone(),
                    category: "/".to_string(),
                    size: None,
                    path: format!("/{name}"),
                })
                .collect())
        }
        async fn strings(&self) -> calxgloss_decomp::Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }
        async fn callers(&self, _address: u64) -> calxgloss_decomp::Result<Vec<String>> {
            Ok(Vec::new())
        }
        async fn xrefs_to(&self, _address: u64) -> calxgloss_decomp::Result<Vec<Xref>> {
            Ok(Vec::new())
        }
        async fn struct_layout(&self, _name: &str) -> calxgloss_decomp::Result<StructLayout> {
            Err(EngineError::NotFound {
                kind: "structure",
                query: String::new(),
            })
        }
        async fn enum_values(&self, _name: &str) -> calxgloss_decomp::Result<EnumDefinition> {
            Err(EngineError::NotFound {
                kind: "enum",
                query: String::new(),
            })
        }
        async fn data_items(&self) -> calxgloss_decomp::Result<Vec<DataItem>> {
            Ok(Vec::new())
        }
        async fn imports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
            Ok(Vec::new())
        }
        async fn exports(&self) -> calxgloss_decomp::Result<Vec<Symbol>> {
            Ok(Vec::new())
        }
        async fn image_base(&self) -> calxgloss_decomp::Result<u64> {
            Ok(0x180000000)
        }
        async fn read_memory(
            &self,
            _address: u64,
            _length: usize,
        ) -> calxgloss_decomp::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    // ------------------------------------------------------------
    // A writer recording every call it receives
    // ------------------------------------------------------------

    #[derive(Default)]
    struct RecordingWriter {
        calls: Mutex<Vec<String>>,
        /// A call whose line contains one of these strings is refused.
        fail_containing: Vec<String>,
    }

    impl RecordingWriter {
        fn record(&self, line: &str) -> calxgloss_decomp::Result<()> {
            self.calls.lock().expect("lock").push(line.to_string());
            if self.fail_containing.iter().any(|bad| line.contains(bad)) {
                return Err(EngineError::Reported {
                    message: format!("refused: {line}"),
                });
            }
            Ok(())
        }

        fn log(&self) -> Vec<String> {
            self.calls.lock().expect("lock").clone()
        }
    }

    impl TypeWriteSource for RecordingWriter {
        async fn set_function_prototype(
            &self,
            function_address: u64,
            prototype: &str,
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!(
                "set_function_prototype {function_address:#x} {prototype}"
            ))
        }
        async fn set_local_variable_type(
            &self,
            function_address: u64,
            variable: &str,
            type_name: &str,
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!(
                "set_local_variable_type {function_address:#x} {variable} {type_name}"
            ))
        }
        async fn create_struct(
            &self,
            name: &str,
            _fields: &[NewStructField<'_>],
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!("create_struct {name}"))
        }
        async fn create_enum(
            &self,
            name: &str,
            _values: &[(&str, i64)],
            _size: u32,
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!("create_enum {name}"))
        }
        async fn create_typedef(
            &self,
            name: &str,
            base_type: &str,
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!("create_typedef {name} {base_type}"))
        }
        async fn add_struct_field(
            &self,
            struct_name: &str,
            field_name: &str,
            field_type: &str,
            _offset: Option<u32>,
        ) -> calxgloss_decomp::Result<()> {
            self.record(&format!(
                "add_struct_field {struct_name} {field_name} {field_type}"
            ))
        }
    }

    // ------------------------------------------------------------
    // Record builders
    // ------------------------------------------------------------

    fn param(
        function: &str,
        index: usize,
        name: &str,
        inferred: &str,
        confidence: u8,
    ) -> InferredType {
        InferredType::Param(InferredParamType {
            function: function.to_string(),
            param_index: index,
            param_name: Some(name.to_string()),
            inferred_type: inferred.to_string(),
            method: crate::types::InferenceMethod::StringFunction,
            scope: crate::types::InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("strlen({name});"),
        })
    }

    fn local(function: &str, name: &str, inferred: &str, confidence: u8) -> InferredType {
        InferredType::Local(InferredLocalType {
            function: function.to_string(),
            variable_name: name.to_string(),
            inferred_type: inferred.to_string(),
            method: crate::types::InferenceMethod::AssignmentChain,
            scope: crate::types::InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: format!("{name} = param_1;"),
        })
    }

    fn call_site(function: &str, callee: &str, arg: &str, inferred: &str) -> InferredType {
        InferredType::CallSite(InferredCallType {
            function: function.to_string(),
            callee: callee.to_string(),
            arg_index: 0,
            arg_name: Some(arg.to_string()),
            inferred_type: inferred.to_string(),
            method: crate::types::InferenceMethod::CrossFunction,
            scope: crate::types::InferenceScope::Function,
            confidence: Confidence::new(70),
            evidence: format!("{callee}({arg});"),
        })
    }

    fn ret(function: &str, inferred: &str, confidence: u8) -> InferredType {
        InferredType::Return(InferredReturnType {
            function: function.to_string(),
            inferred_type: inferred.to_string(),
            method: crate::types::InferenceMethod::ReturnUsage,
            scope: crate::types::InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: "local_8 = FUN_1();".to_string(),
        })
    }

    fn convention(function: &str, convention: CallingConvention, confidence: u8) -> InferredType {
        InferredType::Convention(InferredConvention {
            function: function.to_string(),
            callee: None,
            convention,
            method: crate::types::InferenceMethod::ImportDecoration,
            confidence: Confidence::new(confidence),
            evidence: function.to_string(),
        })
    }

    fn direction(
        function: &str,
        param: &str,
        direction: Direction,
        confidence: u8,
    ) -> InferredType {
        InferredType::Direction(InferredParamDirection {
            function: function.to_string(),
            param_index: 1,
            param_name: Some(param.to_string()),
            direction,
            method: crate::types::InferenceMethod::ParamDirection,
            scope: crate::types::InferenceScope::Function,
            confidence: Confidence::new(confidence),
            evidence: "*param_2 = &local_8;".to_string(),
        })
    }

    fn result(inferences: Vec<InferredType>) -> TypeInferenceResult {
        TypeInferenceResult {
            metadata: ScanMetadata::new("test.dll"),
            inferences,
        }
    }

    /// A program with one function whose body carries an undefined
    /// parameter, an undefined local, and a concrete parameter.
    fn program() -> FakeProgram {
        FakeProgram::new().with_function(
            0x1800_3ab00,
            "FUN_18003ab00",
            "undefined FUN_18003ab00(undefined8 param_1,int param_2)",
            "  undefined8 local_8;\n  strlen(param_1);\n  return;\n",
        )
    }

    async fn apply(
        program: FakeProgram,
        writer: &RecordingWriter,
        inferences: Vec<InferredType>,
        floor: u8,
    ) -> WriteBackReport {
        WriteBack::new(&program, writer, Confidence::new(floor))
            .apply(&result(inferences))
            .await
            .expect("the pass completes")
    }

    // ------------------------------------------------------------
    // Ordering and the three phases
    // ------------------------------------------------------------

    #[tokio::test]
    async fn records_apply_in_three_phases_in_order() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![
                local("FUN_18003ab00", "local_8", "Widget *", 80),
                param("FUN_18003ab00", 0, "param_1", "Widget *", 80),
                ret("FUN_18003ab00", "char *", 80),
            ],
            0,
        )
        .await;
        let log = writer.log();
        assert_eq!(
            log,
            vec![
                // Named types first — Widget is not in the Type Manager.
                "create_typedef Widget undefined".to_string(),
                // Then the prototype, merging param and return readings.
                "set_function_prototype 0x18003ab00 char * FUN_18003ab00(Widget * param_1, int param_2)"
                    .to_string(),
                // Then the local.
                "set_local_variable_type 0x18003ab00 local_8 Widget *".to_string(),
            ]
        );
        assert_eq!(report.types_created, 1);
        assert_eq!(report.applied, 3);
        assert!(report.skipped.is_empty());
        assert!(report.failed.is_empty());
    }

    // ------------------------------------------------------------
    // The confidence floor
    // ------------------------------------------------------------

    #[tokio::test]
    async fn records_below_the_floor_are_skipped_with_a_reason() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "char *", 55),
                param("FUN_18003ab00", 0, "param_1", "char *", 70),
            ],
            70,
        )
        .await;
        assert_eq!(writer.log().len(), 1);
        assert_eq!(report.applied, 1);
        assert_eq!(
            report.skipped,
            [SkippedRecord {
                target: "FUN_18003ab00 param_1".to_string(),
                reason: SkipReason::BelowFloor {
                    confidence: 55,
                    floor: 70,
                },
            }]
        );
    }

    // ------------------------------------------------------------
    // Creating the named types records reference
    // ------------------------------------------------------------

    #[tokio::test]
    async fn a_missing_named_type_is_created_before_the_write_that_needs_it() {
        let writer = RecordingWriter::default();
        apply(
            program(),
            &writer,
            vec![param("FUN_18003ab00", 0, "param_1", "Widget *", 80)],
            0,
        )
        .await;
        let log = writer.log();
        assert_eq!(log[0], "create_typedef Widget undefined");
        assert!(log[1].starts_with("set_function_prototype"));
    }

    #[tokio::test]
    async fn base_types_and_existing_names_are_never_recreated() {
        let writer = RecordingWriter::default();
        let program = program().with_types(&["Widget"]);
        let report = apply(
            program,
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "char *", 80),
                param("FUN_18003ab00", 1, "param_2", "void *", 80),
                local("FUN_18003ab00", "local_8", "Widget *", 80),
            ],
            0,
        )
        .await;
        assert_eq!(report.types_created, 0);
        assert!(!writer.log().iter().any(|call| call.starts_with("create_")));
    }

    #[tokio::test]
    async fn one_named_type_is_created_once_across_several_records() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "Widget *", 80),
                local("FUN_18003ab00", "local_8", "Widget *", 80),
            ],
            0,
        )
        .await;
        assert_eq!(report.types_created, 1);
    }

    // ------------------------------------------------------------
    // Never overwriting a concrete slot
    // ------------------------------------------------------------

    #[tokio::test]
    async fn a_concrete_slot_is_left_alone_and_only_undefined_slots_narrow() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 1, "param_2", "char *", 90),
                local("FUN_18003ab00", "local_8", "char *", 90),
            ],
            0,
        )
        .await;
        // The local narrows; the already-`int` parameter does not.
        assert_eq!(
            writer.log(),
            ["set_local_variable_type 0x18003ab00 local_8 char *".to_string()]
        );
        assert_eq!(report.applied, 1);
        assert_eq!(
            report.skipped,
            [SkippedRecord {
                target: "FUN_18003ab00 param_2".to_string(),
                reason: SkipReason::ConcreteSlot,
            }]
        );
    }

    #[tokio::test]
    async fn a_void_return_is_concrete_and_survives_a_return_reading() {
        let writer = RecordingWriter::default();
        let program = program().with_function(
            0x1800_99000,
            "FUN_180099000",
            "void FUN_180099000(void)",
            "",
        );
        let report = apply(
            program,
            &writer,
            vec![ret("FUN_180099000", "char *", 90)],
            0,
        )
        .await;
        assert!(writer.log().is_empty());
        assert_eq!(
            report.skipped,
            [SkippedRecord {
                target: "FUN_180099000 return".to_string(),
                reason: SkipReason::ConcreteSlot,
            }]
        );
    }

    #[tokio::test]
    async fn the_prototype_merge_keeps_concrete_slots_and_the_name_verbatim() {
        let writer = RecordingWriter::default();
        apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "char *", 80),
                param("FUN_18003ab00", 1, "param_2", "char *", 80),
            ],
            0,
        )
        .await;
        // param_1 narrows, param_2 stays `int`, the name and return stay unchanged.
        assert_eq!(
            writer.log(),
            ["set_function_prototype 0x18003ab00 undefined FUN_18003ab00(char * param_1, int param_2)"
                .to_string()]
        );
    }

    #[tokio::test]
    async fn record_widths_are_written_in_ghidra_spellings() {
        let writer = RecordingWriter::default();
        apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "u32", 80),
                local("FUN_18003ab00", "local_8", "u64", 80),
            ],
            0,
        )
        .await;
        let log = writer.log();
        assert!(log[0].contains("uint param_1"), "{log:?}");
        assert!(log[1].ends_with("local_8 ulonglong"), "{log:?}");
    }

    // ------------------------------------------------------------
    // Error tolerance and the report
    // ------------------------------------------------------------

    #[tokio::test]
    async fn a_failing_write_is_collected_and_the_pass_continues() {
        let writer = RecordingWriter {
            fail_containing: vec!["FUN_18003ab00".to_string()],
            ..Default::default()
        };
        let program = program().with_function(
            0x1800_99000,
            "FUN_180099000",
            "undefined FUN_180099000(void)",
            "",
        );
        let report = apply(
            program,
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "char *", 80),
                ret("FUN_180099000", "char *", 80),
            ],
            0,
        )
        .await;
        // The first write fails; the second function is still written.
        assert_eq!(writer.log().len(), 2);
        assert_eq!(report.applied, 1);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].target, "FUN_18003ab00 param_1");
    }

    #[tokio::test]
    async fn a_function_the_program_does_not_hold_is_skipped() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![param("FUN_ghost", 0, "param_1", "char *", 90)],
            0,
        )
        .await;
        assert!(writer.log().is_empty());
        assert_eq!(
            report.skipped,
            [SkippedRecord {
                target: "FUN_ghost param_1".to_string(),
                reason: SkipReason::FunctionNotFound,
            }]
        );
    }

    #[tokio::test]
    async fn no_placeholder_type_is_created_for_a_record_whose_function_is_missing() {
        // The record names `Widget`, but its function is not in the
        // program — nothing will apply the type, so the Type Manager
        // must not be seeded with a placeholder for it.
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![param("FUN_ghost", 0, "param_1", "Widget *", 90)],
            0,
        )
        .await;
        assert!(writer.log().is_empty());
        assert_eq!(report.types_created, 0);
    }

    #[tokio::test]
    async fn a_local_the_body_does_not_declare_is_skipped() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![local("FUN_18003ab00", "local_ghost", "char *", 90)],
            0,
        )
        .await;
        assert!(writer.log().is_empty());
        assert_eq!(
            report.skipped,
            [SkippedRecord {
                target: "FUN_18003ab00 local_ghost".to_string(),
                reason: SkipReason::SlotNotFound,
            }]
        );
    }

    #[tokio::test]
    async fn site_convention_and_direction_records_are_skipped_as_readings_not_slots() {
        let writer = RecordingWriter::default();
        let report = apply(
            program(),
            &writer,
            vec![
                call_site("FUN_18003ab00", "CloseHandle", "param_2", "void *"),
                convention("CreateFileA@28", CallingConvention::Stdcall, 85),
                direction("FUN_18003ab00", "param_2", Direction::Out, 75),
            ],
            0,
        )
        .await;
        assert!(writer.log().is_empty());
        assert_eq!(
            report.skipped,
            [
                SkippedRecord {
                    target: "FUN_18003ab00 CloseHandle(param_2)".to_string(),
                    reason: SkipReason::CallSiteArgument,
                },
                SkippedRecord {
                    target: "CreateFileA@28 convention".to_string(),
                    reason: SkipReason::Convention,
                },
                SkippedRecord {
                    target: "FUN_18003ab00 param_2 direction".to_string(),
                    reason: SkipReason::Direction,
                },
            ]
        );
    }

    #[tokio::test]
    async fn the_report_counts_applied_skipped_and_failed_together() {
        let writer = RecordingWriter {
            fail_containing: vec!["local_8".to_string()],
            ..Default::default()
        };
        let report = apply(
            program(),
            &writer,
            vec![
                param("FUN_18003ab00", 0, "param_1", "char *", 80), // applied
                param("FUN_18003ab00", 1, "param_2", "char *", 80), // concrete
                local("FUN_18003ab00", "local_8", "char *", 80),    // failed
                param("FUN_18003ab00", 0, "param_1", "char *", 10), // below floor
            ],
            70,
        )
        .await;
        assert_eq!(report.applied, 1);
        assert_eq!(report.skipped.len(), 2);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].target, "FUN_18003ab00 local_8");
    }

    // ------------------------------------------------------------
    // The type-text rules
    // ------------------------------------------------------------

    #[test]
    fn named_type_needed_names_only_creatable_single_types() {
        assert_eq!(named_type_needed("Widget *"), Some("Widget"));
        assert_eq!(named_type_needed("IUnknown *"), Some("IUnknown"));
        assert_eq!(named_type_needed("Color"), Some("Color"));
        assert_eq!(named_type_needed("char *"), None);
        assert_eq!(named_type_needed("void *"), None);
        assert_eq!(named_type_needed("wchar_t *"), None);
        assert_eq!(named_type_needed("u32"), None);
        assert_eq!(named_type_needed("unsigned int"), None);
        assert_eq!(named_type_needed("UdpLibrary::UdpRefCount *"), None);
    }

    #[test]
    fn the_undefined_family_is_what_write_back_narrows() {
        assert!(is_undefined_type("undefined"));
        assert!(is_undefined_type("undefined8"));
        assert!(is_undefined_type("undefined *"));
        assert!(!is_undefined_type("void"));
        assert!(!is_undefined_type("int"));
        assert!(!is_undefined_type("char *"));
        assert!(!is_undefined_type("uint"));
    }

    #[test]
    fn the_signature_split_keeps_everything_the_pass_does_not_narrow() {
        let signature = ParsedSignature::parse(
            "undefined __thiscall FUN_18003ab00(undefined8 param_1,int param_2)",
        )
        .expect("a decompiler signature");
        assert_eq!(signature.return_type, "undefined");
        assert_eq!(signature.convention, ["__thiscall"]);
        assert_eq!(signature.name, "FUN_18003ab00");
        assert_eq!(signature.parameters.len(), 2);
        assert_eq!(signature.parameters[0].type_text, "undefined8");
        assert_eq!(signature.parameters[1].name, "param_2");
        let merged = signature.reassemble(
            "char *",
            &[
                ParsedParameter {
                    type_text: "char *".to_string(),
                    name: "param_1".to_string(),
                },
                signature.parameters[1].clone(),
            ],
        );
        assert_eq!(
            merged,
            "char * __thiscall FUN_18003ab00(char * param_1, int param_2)"
        );
    }
}
