//! Known-library identification scan orchestration.
//!
//! [`LibmatchEngine`] runs the body-signature matcher over every function
//! of one loaded program and assembles its findings into a single
//! [`LibmatchResult`] with its scan provenance.
//!
//! The matcher is pure text analysis over one decompiled body, so the
//! engine fetches each function's pseudo-C exactly once. The scan is one
//! sequential pass over the function listing: keeping the pass
//! sequential keeps the persisted finding list in a stable, diffable
//! order, and where two signatures claim one function the resolution
//! step ([`resolve_matches`](crate::confidence::resolve_matches)) keeps
//! only the strongest claim, standing where the function first appeared.

use std::time::Instant;

use calxgloss_decomp::DecompiledFunction;
use calxgloss_kuna::KunaSource;
use calxgloss_types::{CoverageStatus, FacetCoverage, ScanCoverage};
use tracing::{info, warn};

use crate::error::Result;
use crate::matcher::LibmatchMatcher;
use crate::types::{LibmatchFinding, LibmatchResult, ScanMetadata};

/// The decompiler reads a known-library identification scan performs.
///
/// The shared trait from the decompiler seam crate, re-exported here so
/// the engine's generic shape names it where it always has;
/// [`KunaSource`] implements it over the in-process engine, and tests
/// implement it over canned bodies so the orchestration runs without a
/// server. The futures are `Send` so a scan can be driven from an
/// orchestrating task.
pub use calxgloss_decomp::ScanSource;

/// How many unreached functions one coverage limitation line names inline
/// before folding the remainder into a count — bounded prose beside the
/// counts, not a dump (the P19-3 admitted-semantics track).
const MAX_NAMED_UNREACHED: usize = 5;

/// The facets a libmatch scan declares, in order — the roster the
/// record must name exactly once each. libmatch reads one facet: the
/// decompiled bodies.
pub const DECLARED_FACETS: &[&str] = &["function-bodies"];

/// The coverage record every libmatch scan stamps about itself (issue
/// #347), beside the provenance and the timing.
///
/// libmatch has one facet: `function-bodies`, the decompiled bodies the
/// body-signature matcher reads. The function listing is always read end
/// to end — a failed listing aborts the run, and more than half failing to
/// decompile trips the skip-rate breaker above — so what a finished scan
/// can not have read is exactly the bodies it skipped along the way: a
/// nameless listing entry, or a decompile that failed. With none, the
/// facet is `complete`, and that is the admission's point: a function no
/// finding mentions was examined and clean, never silently unchecked.
/// With any, the facet is `partial` and the limitation line names the
/// unreached bodies (bounded at [`MAX_NAMED_UNREACHED`]), so silence and
/// never-reaching are distinguishable in the filed record itself. The
/// whole picture mirrors the single facet — there is nothing else this
/// engine examines.
fn coverage_stamp(unreached: &[String], nameless: usize) -> ScanCoverage {
    let total = unreached.len() + nameless;
    if total == 0 {
        return ScanCoverage {
            status: CoverageStatus::Complete,
            facets: vec![FacetCoverage {
                id: "function-bodies".to_string(),
                status: CoverageStatus::Complete,
                limitation: None,
            }],
        };
    }
    let mut names = unreached
        .iter()
        .take(MAX_NAMED_UNREACHED)
        .cloned()
        .collect::<Vec<_>>();
    let hidden = unreached.len().saturating_sub(names.len()) + nameless;
    if hidden > 0 {
        names.push(format!("+{hidden} more"));
    }
    let body = if total == 1 { "body" } else { "bodies" };
    ScanCoverage {
        status: CoverageStatus::Partial,
        facets: vec![FacetCoverage {
            id: "function-bodies".to_string(),
            status: CoverageStatus::Partial,
            limitation: Some(format!(
                "{total} function {body} unreached: {}",
                names.join(", ")
            )),
        }],
    }
}

/// Orchestrates the body-signature matcher into one [`LibmatchResult`].
///
/// The engine is generic over its [`ScanSource`], so tests can run the
/// whole orchestration over canned bodies; [`new`](Self::new) builds one
/// over a loaded [`KunaSource`]. The matcher carries no state and starts
/// with the built-in starter set —
/// [`with_matcher`](Self::with_matcher) swaps the set whole — so one
/// instance serves the whole scan.
#[derive(Debug, Clone)]
pub struct LibmatchEngine<S = KunaSource> {
    source: S,
    matcher: LibmatchMatcher,
}

impl LibmatchEngine<KunaSource> {
    /// An engine over a loaded Kuna program, scanning with the built-in
    /// starter signature set.
    pub fn new(source: &KunaSource) -> LibmatchEngine<KunaSource> {
        LibmatchEngine {
            source: source.clone(),
            matcher: LibmatchMatcher::with_default_signatures(),
        }
    }
}

impl<S> LibmatchEngine<S> {
    /// An engine whose decompiles come from `source`, scanning with the
    /// built-in starter signature set.
    pub fn with_source(source: S) -> Self {
        LibmatchEngine {
            source,
            matcher: LibmatchMatcher::with_default_signatures(),
        }
    }

    /// Match bodies against `matcher`'s signature set instead of the
    /// built-in starter set.
    pub fn with_matcher(mut self, matcher: LibmatchMatcher) -> Self {
        self.matcher = matcher;
        self
    }

    /// Match bodies against an operator-supplied
    /// [database](crate::signature_db::SignatureDatabase)'s signature
    /// set instead of the built-in starter set — the file's set
    /// replaces the built-in one whole, never merged into it.
    pub fn with_signature_database(
        mut self,
        database: crate::signature_db::SignatureDatabase,
    ) -> Self {
        self.matcher = LibmatchMatcher::with_signatures(database.signatures);
        self
    }

    /// Identify known-library functions across `binary`, decompiling
    /// each function exactly once and matching its normalized body
    /// against every configured signature.
    ///
    /// `binary` names the program the scan reads (e.g. `eqmain.dll`) and
    /// becomes the key a persisted result is filed under. The findings
    /// follow the function listing — function by function, and within
    /// one function the signature matches in configuration order — so
    /// two scans of the same program diff cleanly. Where two signatures
    /// claim one function, only the strongest claim survives resolution,
    /// standing where the function first appeared. Cross-function
    /// propagation findings — identical-body duplicates and tail-call
    /// thunks inheriting a match — append after every per-function
    /// finding, identical-body findings first and thunks after, each
    /// group in listing order.
    ///
    /// A function whose body the decompiler cannot produce (a thunk, a
    /// bad entry point) is skipped with a warning; only a failure of the
    /// listing itself — the engine being down — aborts the run, since
    /// then nothing was scanned. But when more than half the listing
    /// fails to decompile, the skip-rate breaker aborts the run too:
    /// that is the signature of the engine answering from the wrong
    /// program, and skipping on would persist a phantom-clean record
    /// (issue #71).
    pub async fn scan(&self, binary: impl Into<String>) -> Result<LibmatchResult>
    where
        S: ScanSource,
    {
        let started = Instant::now();
        let functions = self.source.functions().await?;

        let mut findings: Vec<LibmatchFinding> = Vec::new();
        let mut bodies: Vec<DecompiledFunction> = Vec::new();
        let mut skipped = 0usize;
        let mut decompile_failures = 0usize;
        // P19-3: which bodies the scan could NOT read, named where a name
        // exists, counted where the listing entry is nameless — the
        // coverage record below states it, so an unmentioned function
        // means examined-and-clean, never silently unchecked.
        let mut unreached: Vec<String> = Vec::new();
        let mut nameless = 0usize;
        for function in &functions {
            if function.name.is_empty() {
                // A nameless listing entry would send the name lookup
                // wandering into some other function's body; nothing
                // can be said about it, so it passes unrecorded.
                warn!(
                    address = format_args!("{:#x}", function.address),
                    "Skipping function with no name"
                );
                skipped += 1;
                nameless += 1;
                continue;
            }
            let decompiled: DecompiledFunction = match self.source.decompile(&function.name).await {
                Ok(decompiled) => decompiled,
                Err(error) => {
                    warn!(
                        function = %function.name,
                        error = %error,
                        "Skipping function: decompile failed"
                    );
                    skipped += 1;
                    decompile_failures += 1;
                    unreached.push(function.name.clone());
                    // Skip-rate breaker: once most of the listing has
                    // failed to decompile, the scan is reading a program
                    // the engine cannot analyze, and an empty result
                    // would persist as a phantom-clean record. Abort
                    // with the counts instead of skipping on.
                    if decompile_failures * 2 > functions.len() {
                        return Err(crate::LibmatchError::DecompileBreaker {
                            failed: decompile_failures,
                            total: functions.len(),
                        });
                    }
                    continue;
                }
            };

            findings.extend(self.matcher.match_function(&decompiled));
            bodies.push(decompiled);
        }

        // Two signatures can fit one body; one function is one function,
        // so the strongest claim per function stands, in listing order
        // (ADR-0022's precedent).
        let mut findings = crate::confidence::resolve_matches(findings);

        // The cross-function pass then propagates those claims over the
        // bodies the scan already holds — no extra engine reads — and
        // its findings append after every per-function finding,
        // identical-body duplicates first and thunks after, each group
        // in listing order.
        findings.extend(crate::cross_function::propagate(&bodies, &findings));

        let mut metadata = ScanMetadata::new(binary);
        // The source names its engine and pin under `kuna` (issue #208).
        metadata.engine = self.source.engine_provenance();
        // The engine admits its own coverage inside its own scan, where
        // the truth lives — not the registry row and not the CLI (issue
        // #347): every listed body was read unless the scan says which
        // ones it could not reach, and the match records themselves carry
        // their version-authority note. The batch scan phase and the
        // CLI's force-rescan file the same admission through the same
        // single definition.
        metadata.coverage = Some(coverage_stamp(&unreached, nameless));
        metadata.duration_secs = started.elapsed().as_secs();
        info!(
            binary = %metadata.binary,
            functions = functions.len(),
            findings = findings.len(),
            skipped,
            duration_secs = metadata.duration_secs,
            "Identified known-library functions"
        );
        Ok(LibmatchResult { metadata, findings })
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::LibmatchMatcher;
    use crate::signature::LibmatchSignature;
    use crate::signature_db::SignatureDatabase;
    use crate::types::LibraryFamily;
    use calxgloss_decomp::{
        DataItem, DataTypeEntry, DecompiledFunction, EngineError, EnumDefinition, FunctionSummary,
        Result, StringLiteral, StructLayout, Symbol, Xref,
    };
    use std::collections::HashMap;

    fn summary(name: &str) -> FunctionSummary {
        FunctionSummary {
            name: name.to_string(),
            address: 0x1800_3ab00,
        }
    }

    fn function(name: &str, signature: &str, body: &str) -> DecompiledFunction {
        DecompiledFunction {
            name: name.to_string(),
            signature: signature.to_string(),
            body: format!("\n{signature}\n\n{{\n{body}}}\n"),
        }
    }

    /// A canned program implementing [`ScanSource`], so the whole
    /// orchestration runs without a server.
    #[derive(Clone, Default)]
    struct FakeProgram {
        listing: Vec<FunctionSummary>,
        bodies: HashMap<String, DecompiledFunction>,
        fail_decompiles: Vec<String>,
        fail_listing: bool,
    }

    impl ScanSource for FakeProgram {
        async fn functions(&self) -> Result<Vec<FunctionSummary>> {
            if self.fail_listing {
                return Err(EngineError::Reported {
                    message: "the engine is busy".into(),
                });
            }
            Ok(self.listing.clone())
        }

        async fn decompile(&self, name: &str) -> Result<DecompiledFunction> {
            if self.fail_decompiles.iter().any(|f| f == name) {
                return Err(EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                });
            }
            self.bodies
                .get(name)
                .cloned()
                .ok_or_else(|| EngineError::NotFound {
                    kind: "function",
                    query: name.to_string(),
                })
        }

        // The rest of the shared trait's reads: this engine never makes
        // them, so they answer with empty or not-found data.
        async fn strings(&self) -> Result<Vec<StringLiteral>> {
            Ok(Vec::new())
        }

        async fn callers(&self, _address: u64) -> Result<Vec<String>> {
            Ok(Vec::new())
        }

        async fn xrefs_to(&self, _address: u64) -> Result<Vec<Xref>> {
            Ok(Vec::new())
        }

        async fn data_types(&self, _category: Option<&str>) -> Result<Vec<DataTypeEntry>> {
            Ok(Vec::new())
        }

        async fn struct_layout(&self, name: &str) -> Result<StructLayout> {
            Err(EngineError::NotFound {
                kind: "struct",
                query: name.to_string(),
            })
        }

        async fn enum_values(&self, name: &str) -> Result<EnumDefinition> {
            Err(EngineError::NotFound {
                kind: "enum",
                query: name.to_string(),
            })
        }

        async fn data_items(&self) -> Result<Vec<DataItem>> {
            Ok(Vec::new())
        }

        async fn imports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn exports(&self) -> Result<Vec<Symbol>> {
            Ok(Vec::new())
        }

        async fn image_base(&self) -> Result<u64> {
            Ok(0)
        }

        async fn read_memory(&self, _address: u64, _length: usize) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        // The fake source names itself, so the tests can pin that
        // scan() stamps the source's provenance onto the record (#208).
        fn engine_provenance(&self) -> Option<calxgloss_types::EngineProvenance> {
            Some(calxgloss_types::EngineProvenance {
                name: "fake-engine".into(),
                version: Some("9.9".into()),
                fingerprint: Some("0123456".into()),
            })
        }
    }

    /// The MSVC CRT byte-copy loop as Ghidra decompiles it: a countdown,
    /// a dereference assignment, and a `!= 0` loop test, with no guard
    /// branch.
    const MEMCPY_BODY: &str = "\
  puVar1 = param_1 + 1;
  lVar2 = param_2 + 1;
  do {
    param_3 = param_3 + -1;
    *(undefined8 *)((long)puVar1 + -8) = *(undefined8 *)((long)lVar2 + -8);
    lVar2 = lVar2 + 8;
    puVar1 = puVar1 + 8;
  } while (param_3 != 0);
  return param_1;
";

    /// The same copy loop as a different function's decompile: different
    /// Ghidra variable names, a register temporary, and a volatile
    /// data-address write — nothing that is part of the routine's shape.
    const MEMCPY_LOOKALIKE_BODY: &str = "\
  uVar4 = DAT_180047b10;
  puVar7 = param_1 + 1;
  lVar9 = param_2 + 1;
  in_DL = 0x180045a68;
  do {
    param_3 = param_3 + -1;
    *(undefined8 *)((long)puVar7 + -8) = *(undefined8 *)((long)lVar9 + -8);
    lVar9 = lVar9 + 8;
    puVar7 = puVar7 + 8;
  } while (param_3 != 0);
  return param_1;
";

    /// A body that is not a library routine: a plain function.
    const PLAIN_BODY: &str = "  return;\n";

    /// A copy loop with a guard branch — the overlap check that makes
    /// the shape a memmove, which the starter set does not claim.
    const GUARDED_COPY_BODY: &str = "\
  puVar1 = param_1;
  if (param_2 < param_1) {
    puVar1 = param_1 + param_3;
    param_2 = param_2 + param_3;
  }
  do {
    param_3 = param_3 + -1;
    *(undefined *)((long)puVar1 + -1) = *(undefined *)((long)param_2 + -1);
  } while (param_3 != 0);
  return param_1;
";

    /// The copy loop again, but allocating its destination first — the
    /// `malloc` call line is what required and forbidden callee
    /// references gate on.
    const ALLOCATING_COPY_BODY: &str = "\
  puVar1 = malloc(param_3);
  lVar2 = param_2;
  do {
    param_3 = param_3 + -1;
    *(undefined *)((long)puVar1 + -1) = *(undefined *)((long)lVar2 + -1);
    lVar2 = lVar2 + 1;
    puVar1 = puVar1 + 1;
  } while (param_3 != 0);
  return puVar1;
";

    /// The MSVC CRT byte-fill loop: the copy loop's countdown and loop
    /// test, but the store carries a cast byte instead of a source read.
    const MEMSET_BODY: &str = "\
  puVar1 = (byte *)param_1;
  do {
    param_3 = param_3 + -1;
    *puVar1 = (char)param_2;
    puVar1 = puVar1 + 1;
  } while (param_3 != 0);
  return param_1;
";

    /// The MSVC CRT byte-compare loop: unsigned byte loads from two
    /// pointers, a difference on mismatch, and the copy loop's
    /// countdown — with no store line.
    const MEMCMP_BODY: &str = "\
  do {
    cVar1 = *(uchar *)param_1;
    cVar2 = *(uchar *)param_2;
    if (cVar1 != cVar2) {
      uVar4 = (uint)cVar1 - (uint)cVar2;
      goto joined_r0x180045a68;
    }
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
    param_3 = param_3 + -1;
  } while (param_3 != 0);
  uVar4 = 0;
  return (int)uVar4;
";

    /// The MSVC CRT string-length scan: walk the pointer itself until
    /// the NUL byte, counting as you go.
    const STRLEN_BODY: &str = "\
  sVar1 = 0;
  while (*param_1 != '\\0') {
    param_1 = param_1 + 1;
    sVar1 = sVar1 + 1;
  }
  return sVar1;
";

    /// The MSVC CRT string compare: byte loads from both strings, an
    /// equality carry line, and the loop test that stops on the NUL
    /// byte.
    const STRCMP_BODY: &str = "\
  do {
    cVar1 = *param_1;
    cVar2 = *param_2;
    bVar3 = cVar1 == cVar2;
    param_1 = param_1 + 1;
    param_2 = param_2 + 1;
  } while (bVar3 && (cVar1 != '\\0'));
  iVar4 = (int)(uint)(byte)cVar1 - (int)(uint)(byte)cVar2;
  return iVar4;
";

    /// The MSVC CRT string copy: a byte load, a bare byte store, and
    /// the NUL-terminated loop — the copy that carries the terminator.
    const STRCPY_BODY: &str = "\
  puVar2 = param_1;
  do {
    cVar1 = *param_2;
    param_2 = param_2 + 1;
    *puVar2 = cVar1;
    puVar2 = puVar2 + 1;
  } while (cVar1 != '\\0');
  return param_1;
";

    /// The MSVC CRT `operator new` wrapper: a `malloc` call with a null
    /// test and a new-handler retry.
    const OPERATOR_NEW_BODY: &str = "\
  pvVar1 = malloc(param_1);
  if (pvVar1 == (void *)0x0) {
    FUN_180045e00();
    pvVar1 = malloc(param_1);
  }
  return pvVar1;
";

    /// The MSVC CRT `operator delete` wrapper: a guarded `free`.
    const OPERATOR_DELETE_BODY: &str = "\
  if (param_1 != (void *)0x0) {
    free(param_1);
  }
  return;
";

    /// The STL associative-container red-black rotation: the three-line
    /// child rehang spelled by the MSVC node fields, with the parent
    /// rewire around it.
    const TREE_ROTATE_BODY: &str = "\
  pVar1 = param_1->_Right;
  param_1->_Right = pVar1->_Left;
  pVar1->_Left = param_1;
  pVar2 = param_1->_Parent;
  if (param_1 == pVar2->_Right) {
    pVar2->_Right = pVar1;
  }
  else {
    pVar2->_Left = pVar1;
  }
  pVar1->_Parent = pVar2;
  param_1->_Parent = pVar1;
  return;
";

    /// The STL associative-container search descent: walk
    /// `_Left`/`_Right` by key comparison while testing `_Isnil`.
    const TREE_SEARCH_BODY: &str = "\
  pVar2 = param_1;
  cVar1 = pVar2->_Isnil;
  while (cVar1 == '\\0') {
    if (*(long *)param_2 < *(long *)&pVar2->_Left) {
      pVar2 = pVar2->_Left;
    }
    else {
      pVar2 = pVar2->_Right;
    }
    cVar1 = pVar2->_Isnil;
  }
  return pVar2;
";

    // The same shapes as Kuna (the only engine, ADR-0041) renders them:
    // every spelling below is one observed in the fixture target's Kuna
    // decompiles (issue #309) — `a0`-family parameters and `v1`-family
    // temporaries, the truth test `} while (v2);` and `while (v1) {`
    // beside the `!= 0` form, the countdown `v2 = v2 - 1`, the indexed
    // pointer step `v1 = &v1[1]`, the `uint1` byte type, the falseness
    // test `if (!a0)`, and the `sub_…` name for an unnamed routine. The
    // dialect layer folds the invented names onto the same wildcard
    // tokens, and the corpus test in `tests/kuna_corpus.rs` pins the
    // shapes Kuna really emits; these fakes pin the rest of the set
    // speaking the dialect too.

    const KUNA_MEMCPY_BODY: &str = "\
  uint8 *v1; // rax | rdi
  uint8 *v2; // rdx | rsi

  v1 = a0;
  v2 = a1;
  do {
    a2 = a2 + -1;
    *(uint8 *)((uint8 *)v1 + a2) = *(uint8 *)((uint8 *)v2 + a2);
  } while (a2);
  return a0;
";

    const KUNA_MEMSET_BODY: &str = "\
  char *v1; // rax | rdi

  v1 = (char *)a0;
  do {
    a1 = a1 + -1;
    *v1 = (char)a2;
    v1 = &v1[1];
  } while (a1);
  return a0;
";

    const KUNA_MEMCMP_BODY: &str = "\
  uint1 v1; // r8
  uint1 v2; // r9

  do {
    v1 = *(uint1 *)a0;
    v2 = *(uint1 *)a1;
    if (v1 != v2)
      return (int4)v1 - (int4)v2;
    a0 = &a0[1];
    a1 = &a1[1];
    a2 = a2 - 1;
  } while (a2);
  return 0;
";

    const KUNA_STRLEN_BODY: &str = "\
  uint8 v1; // rax

  v1 = 0;
  while (*a0) {
    a0 = &a0[1];
    v1 = v1 + 1;
  }
  return v1;
";

    const KUNA_STRCPY_BODY: &str = "\
  char v1; // dl

  v1 = *a1;
  *a0 = v1;
  while (v1) {
    a1 = &a1[1];
    v1 = *a1;
    a0 = &a0[1];
    *a0 = v1;
  }
  return a0;
";

    const KUNA_OPERATOR_NEW_BODY: &str = "\
  void *v1; // rax

  v1 = malloc(a0);
  if (!v1) {
    sub_293061e00();
    v1 = malloc(a0);
  }
  return v1;
";

    const KUNA_OPERATOR_DELETE_BODY: &str = "\
  if (!a0)
    return;
  free(a0); // tail-call
  return;
";

    const KUNA_TREE_ROTATE_BODY: &str = "\
  struct_7 *v1; // rcx
  struct_7 *v2; // rdx

  v1 = a0->_Right;
  a0->_Right = v1->_Left;
  v1->_Left = a0;
  v2 = a0->_Parent;
  if (a0 == v2->_Right)
    v2->_Right = v1;
  else
    v2->_Left = v1;
  v1->_Parent = v2;
  a0->_Parent = v1;
  return;
";

    const KUNA_TREE_SEARCH_BODY: &str = "\
  bool v1; // zf
  struct_7 *v2; // rbx

  v2 = a0;
  v1 = v2->_Isnil;
  while (!v1) {
    if (*(uint8 *)a1 < *(uint8 *)&v2->_Left)
      v2 = v2->_Left;
    else
      v2 = v2->_Right;
    v1 = v2->_Isnil;
  }
  return v2;
";

    /// The canned program: one function whose body is the memcpy idiom,
    /// one plain function that matches nothing, and one guarded copy
    /// the starter set vetoes.
    fn program() -> FakeProgram {
        let mut program = tests::FakeProgram {
            listing: vec![
                summary("FUN_18003ab00"),
                summary("FUN_18003e750"),
                summary("FUN_1800412a0"),
            ],
            ..Default::default()
        };
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined8 * __fastcall FUN_18003ab00(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        program.bodies.insert(
            "FUN_18003e750".into(),
            function("FUN_18003e750", "undefined FUN_18003e750(void)", PLAIN_BODY),
        );
        program.bodies.insert(
            "FUN_1800412a0".into(),
            function(
                "FUN_1800412a0",
                "undefined8 * __fastcall FUN_1800412a0(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                GUARDED_COPY_BODY,
            ),
        );
        program
    }

    /// The matcher for the linker-folded-copy tests: the memcpy
    /// signature additionally vetoes `thunk_` prototype lines, so a
    /// folded copy named `thunk_…` makes no claim of its own and can
    /// only inherit the match through the cross-function pass.
    fn folded_copy_matcher() -> LibmatchMatcher {
        LibmatchMatcher::with_signatures([LibmatchSignature::new(
            "memcpy",
            LibraryFamily::Crt,
            [
                r"\*\([^;]*\) = \*\(",
                r"VAR = VAR \+ -1",
                r"while \(VAR != 0\)",
            ],
            "slice copy",
        )
        .with_exclusions([r"\bif \(", r"thunk_"])])
    }

    async fn scan(program: FakeProgram) -> LibmatchResult {
        LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await
            .expect("scan")
    }

    #[tokio::test]
    async fn a_body_matching_a_builtin_signature_lands_a_finding() {
        let result = scan(program()).await;

        assert_eq!(result.metadata.binary, "eqmain.dll");
        assert!(result.metadata.scanned_at > 0);

        let findings: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(findings.len(), 1, "the memcpy idiom matches one signature");
        let finding = findings[0];
        assert_eq!(finding.kind(), "body_signature");
        assert_eq!(finding.target(), "memcpy");
        assert_eq!(finding.family(), LibraryFamily::Crt);
        // The standard body-evidence score.
        assert_eq!(
            finding.confidence().value(),
            crate::confidence::BODY_MATCH_CONFIDENCE
        );
        assert!(!finding.evidence().is_empty());
        assert!(finding.evidence().contains("= *(undefined8"));
        assert!(!finding.suggestion().is_empty());
    }

    #[tokio::test]
    async fn unmatched_bodies_land_no_findings() {
        let result = scan(program()).await;

        // The plain function and the guarded copy (a memmove shape the
        // starter set vetoes) carry nothing, and the scan changes
        // nothing else about the result.
        assert!(result.for_function("FUN_18003e750").next().is_none());
        assert!(result.for_function("FUN_1800412a0").next().is_none());
        assert_eq!(result.findings.len(), 1);
    }

    #[tokio::test]
    async fn bodies_differing_only_in_names_temporaries_and_addresses_match_the_same_signature() {
        // Two decompiles of the same routine: different Ghidra variable
        // names, a register temporary, and a volatile data address in
        // one, plain names in the other. Both must land the same
        // finding — asserted through scan findings, never through
        // normalization internals.
        let mut program = program();
        program.listing.push(summary("FUN_180098765"));
        program.bodies.insert(
            "FUN_180098765".into(),
            function(
                "FUN_180098765",
                "undefined8 * __fastcall FUN_180098765(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_LOOKALIKE_BODY,
            ),
        );
        let result = scan(program).await;

        for name in ["FUN_18003ab00", "FUN_180098765"] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} must match the memcpy signature");
            assert_eq!(findings[0].target(), "memcpy");
            assert_eq!(findings[0].family(), LibraryFamily::Crt);
        }
    }

    /// A program carrying one representative body per built-in starter-set
    /// shape the tracer bullet's set did not yet cover: the grown CRT
    /// memory/string set, the allocator wrappers, and the STL tree
    /// idioms.
    fn starter_set_program() -> FakeProgram {
        let mut program = FakeProgram::default();
        for (name, signature, body) in [
            (
                "FUN_18003ac00",
                "void * __fastcall FUN_18003ac00(void *param_1,int param_2,size_t param_3)",
                MEMSET_BODY,
            ),
            (
                "FUN_18003ad00",
                "int __fastcall FUN_18003ad00(long param_1,long param_2,size_t param_3)",
                MEMCMP_BODY,
            ),
            (
                "FUN_18003ae00",
                "size_t __fastcall FUN_18003ae00(long param_1)",
                STRLEN_BODY,
            ),
            (
                "FUN_18003af00",
                "int __fastcall FUN_18003af00(char *param_1,char *param_2)",
                STRCMP_BODY,
            ),
            (
                "FUN_18003b000",
                "char * __fastcall FUN_18003b000(char *param_1,char *param_2)",
                STRCPY_BODY,
            ),
            (
                "FUN_180045f00",
                "void * __fastcall FUN_180045f00(size_t param_1)",
                OPERATOR_NEW_BODY,
            ),
            (
                "FUN_180045f40",
                "void __fastcall FUN_180045f40(void *param_1)",
                OPERATOR_DELETE_BODY,
            ),
            (
                "FUN_18004abcd",
                "void __fastcall FUN_18004abcd(std::_Tree_node *param_1)",
                TREE_ROTATE_BODY,
            ),
            (
                "FUN_18004d120",
                "std::_Tree_node * __fastcall FUN_18004d120(std::_Tree_node *param_1,long param_2)",
                TREE_SEARCH_BODY,
            ),
        ] {
            program.listing.push(summary(name));
            program
                .bodies
                .insert(name.into(), function(name, signature, body));
        }
        program
    }

    #[tokio::test]
    async fn crt_memory_and_string_bodies_land_their_own_symbols() {
        // Each representative MSVC CRT memory/string body lands exactly
        // one finding, naming its own symbol and the CRT family at the
        // standard score: the grown starter set's entries must not
        // cross-claim each other's shapes.
        let result = scan(starter_set_program()).await;
        for (name, symbol) in [
            ("FUN_18003ac00", "memset"),
            ("FUN_18003ad00", "memcmp"),
            ("FUN_18003ae00", "strlen"),
            ("FUN_18003af00", "strcmp"),
            ("FUN_18003b000", "strcpy"),
        ] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} lands exactly one claim");
            assert_eq!(findings[0].target(), symbol);
            assert_eq!(findings[0].family(), LibraryFamily::Crt);
            assert_eq!(
                findings[0].confidence().value(),
                crate::confidence::BODY_MATCH_CONFIDENCE
            );
        }
    }

    #[tokio::test]
    async fn allocator_wrapper_bodies_land_crt_findings_at_their_sloppier_score() {
        // The `operator new`/`operator delete` wrappers: a `malloc`/`free`
        // call plus a null test is thin evidence — any allocation helper
        // reads alike — so these entries deliberately claim a sloppier
        // score than the standard body-evidence one, through the
        // per-entry override.
        let result = scan(starter_set_program()).await;
        for (name, symbol) in [
            ("FUN_180045f00", "operator new"),
            ("FUN_180045f40", "operator delete"),
        ] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} lands exactly one claim");
            assert_eq!(findings[0].target(), symbol);
            assert_eq!(findings[0].family(), LibraryFamily::Crt);
            assert_eq!(
                findings[0].confidence().value(),
                50,
                "the wrapper entries score below the standard body-evidence score"
            );
        }
    }

    #[tokio::test]
    async fn stl_tree_idiom_bodies_land_findings_naming_the_stl_family() {
        // The associative-container red-black-tree idioms: the rotation
        // the rebalancing pass compiles to and the search descent that
        // walks `_Left`/`_Right` while testing `_Isnil`. The MSVC node
        // fields survive normalization, and both bodies land the tree
        // entries naming the STL family at the standard score.
        let result = scan(starter_set_program()).await;
        for (name, symbol) in [
            ("FUN_18004abcd", "std::_Tree::_Rotate_left"),
            ("FUN_18004d120", "std::_Tree::_Lower_bound"),
        ] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} lands exactly one claim");
            assert_eq!(findings[0].target(), symbol);
            assert_eq!(findings[0].family(), LibraryFamily::Stl);
            assert_eq!(
                findings[0].confidence().value(),
                crate::confidence::BODY_MATCH_CONFIDENCE
            );
        }
    }

    /// A program carrying one body per built-in starter-set shape, each
    /// spelled as Kuna renders it: the dialect the only engine emits,
    /// with every invented name folded by the normalizer's Kuna layer
    /// (issue #309).
    fn kuna_starter_set_program() -> FakeProgram {
        let mut program = FakeProgram::default();
        for (name, signature, body) in [
            (
                "sub_293061a00",
                "void * sub_293061a00(void *a0,void *a1,uint8 a2)",
                KUNA_MEMCPY_BODY,
            ),
            (
                "sub_293061b00",
                "void * sub_293061b00(void *a0,int4 a1,uint8 a2)",
                KUNA_MEMSET_BODY,
            ),
            (
                "sub_293061c00",
                "int4 sub_293061c00(void *a0,void *a1,uint8 a2)",
                KUNA_MEMCMP_BODY,
            ),
            (
                "sub_293061d00",
                "uint8 sub_293061d00(char *a0)",
                KUNA_STRLEN_BODY,
            ),
            (
                "sub_293061e00",
                "char * sub_293061e00(char *a0,char *a1)",
                KUNA_STRCPY_BODY,
            ),
            (
                "sub_293061f00",
                "void * sub_293061f00(uint8 a0)",
                KUNA_OPERATOR_NEW_BODY,
            ),
            (
                "sub_293061f40",
                "void sub_293061f40(void *a0)",
                KUNA_OPERATOR_DELETE_BODY,
            ),
            (
                "sub_2930620a0",
                "void sub_2930620a0(struct_7 *a0)",
                KUNA_TREE_ROTATE_BODY,
            ),
            (
                "sub_293062120",
                "struct_7 * sub_293062120(struct_7 *a0,uint8 *a1)",
                KUNA_TREE_SEARCH_BODY,
            ),
        ] {
            program.listing.push(summary(name));
            program
                .bodies
                .insert(name.into(), function(name, signature, body));
        }
        program
    }

    #[tokio::test]
    async fn kuna_dialect_bodies_land_the_same_symbols_as_the_ghidra_ones() {
        // One shared shape rule, one signature set: every starter-set
        // entry must also speak Kuna, the only engine (issue #309).
        // Each Kuna-spelled body lands exactly one finding naming the
        // same symbol and family as its Ghidra twin — the dialect
        // layer folds the invented names, and the corpus-grounded
        // bundle alternatives land the loop tests and steps.
        let result = scan(kuna_starter_set_program()).await;
        for (name, symbol, family) in [
            ("sub_293061a00", "memcpy", LibraryFamily::Crt),
            ("sub_293061b00", "memset", LibraryFamily::Crt),
            ("sub_293061c00", "memcmp", LibraryFamily::Crt),
            ("sub_293061d00", "strlen", LibraryFamily::Crt),
            ("sub_293061e00", "strcpy", LibraryFamily::Crt),
            ("sub_293061f00", "operator new", LibraryFamily::Crt),
            ("sub_293061f40", "operator delete", LibraryFamily::Crt),
            (
                "sub_2930620a0",
                "std::_Tree::_Rotate_left",
                LibraryFamily::Stl,
            ),
            (
                "sub_293062120",
                "std::_Tree::_Lower_bound",
                LibraryFamily::Stl,
            ),
        ] {
            let findings: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(findings.len(), 1, "{name} lands exactly one claim");
            assert_eq!(findings[0].target(), symbol, "{name} names its symbol");
            assert_eq!(findings[0].family(), family);
            let expected_score = match symbol {
                "operator new" | "operator delete" => 50,
                _ => crate::confidence::BODY_MATCH_CONFIDENCE,
            };
            assert_eq!(findings[0].confidence().value(), expected_score);
        }
    }

    #[tokio::test]
    async fn scan_keeps_findings_in_scan_order() {
        // Both functions carry the memcpy idiom, so the persisted list
        // must group their findings by function in listing order —
        // never interleaved.
        let mut program = program();
        program.listing = vec![summary("FUN_18003e750"), summary("FUN_18003ab00")];
        program.bodies.insert(
            "FUN_18003e750".into(),
            function(
                "FUN_18003e750",
                "undefined8 * __fastcall FUN_18003e750(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_LOOKALIKE_BODY,
            ),
        );
        let result = scan(program).await;

        let order: Vec<(&str, &str)> = result
            .findings
            .iter()
            .map(|finding| (finding.function(), finding.kind()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("FUN_18003e750", "body_signature"),
                ("FUN_18003ab00", "body_signature"),
            ]
        );
    }

    #[tokio::test]
    async fn competing_matches_for_one_function_resolve_to_the_strongest() {
        // A broad copy-loop shape and the memcpy signature both claim
        // the same function; the scan reports the stronger claim once,
        // standing where the function first appeared (ADR-0022).
        let matcher = LibmatchMatcher::with_signatures([
            LibmatchSignature::new("copy_loop", LibraryFamily::Crt, [r"while \("], "slice copy")
                .with_confidence(60),
            LibmatchSignature::new(
                "memcpy",
                LibraryFamily::Crt,
                [
                    r"VAR = VAR \+ -1",
                    r"\*\([^;]*\) = \*\(",
                    r"while \(VAR != 0\)",
                ],
                "slice copy",
            )
            .with_confidence(70),
        ]);
        let result = LibmatchEngine::with_source(program())
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(claims.len(), 1, "one claim per function");
        assert_eq!(claims[0].target(), "memcpy");
        assert_eq!(claims[0].confidence().value(), 70);
    }

    #[tokio::test]
    async fn an_identical_body_duplicate_inherits_the_matched_symbol() {
        // A linker-folded (COMDAT/ICF) copy of a matched body: Ghidra
        // names the second copy `thunk_…`, and the signature's
        // exclusion vetoes that prototype line, so the duplicate makes
        // no claim of its own — but its body is identical to the
        // matched body's normalized shape, so it inherits the match.
        let matcher = folded_copy_matcher();
        let mut program = program();
        program.listing.push(summary("thunk_FUN_180099999"));
        program.bodies.insert(
            "thunk_FUN_180099999".into(),
            function(
                "thunk_FUN_180099999",
                "undefined8 * __fastcall thunk_FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        let result = LibmatchEngine::with_source(program)
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let claims: Vec<&LibmatchFinding> = result.for_function("thunk_FUN_180099999").collect();
        assert_eq!(claims.len(), 1, "the duplicate inherits one claim");
        assert_eq!(claims[0].kind(), "identical_body");
        assert_eq!(
            claims[0].target(),
            "memcpy",
            "the duplicate names the same matched symbol"
        );
        assert_eq!(claims[0].family(), LibraryFamily::Crt);
        assert_eq!(
            claims[0].confidence().value(),
            crate::confidence::BODY_MATCH_CONFIDENCE,
            "an identical body is the same body: it inherits the match whole, penalty-free"
        );
        assert!(
            claims[0].evidence().contains("= *(undefined8"),
            "the evidence is the duplicate's own body line, not the matched body's"
        );
    }

    #[tokio::test]
    async fn a_tail_call_thunk_inherits_the_match_at_a_penalized_confidence() {
        // A one-line thunk: its whole body is a tail call to a matched
        // function, so it inherits that match — at a confidence penalty,
        // because the call line is thinner evidence than the matched
        // body's own shape.
        let mut program = program();
        program.listing.push(summary("thunk_FUN_180099999"));
        program.bodies.insert(
            "thunk_FUN_180099999".into(),
            function(
                "thunk_FUN_180099999",
                "undefined8 * __fastcall thunk_FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  return FUN_18003ab00(param_1, param_2, param_3);\n",
            ),
        );
        let result = scan(program).await;

        let claims: Vec<&LibmatchFinding> = result.for_function("thunk_FUN_180099999").collect();
        assert_eq!(claims.len(), 1, "the thunk inherits one claim");
        assert_eq!(claims[0].kind(), "tail_call_thunk");
        assert_eq!(claims[0].target(), "memcpy");
        assert_eq!(claims[0].family(), LibraryFamily::Crt);
        assert_eq!(
            claims[0].confidence().value(),
            50,
            "the match is inherited at the penalty below the matched body's score"
        );
        assert_eq!(
            claims[0].evidence(),
            "return FUN_18003ab00(param_1, param_2, param_3);",
            "the evidence is the thunk's own call line"
        );
    }

    #[tokio::test]
    async fn a_chain_of_tail_call_thunks_collapses_onto_the_matched_function() {
        // Two thunks deep, listed farthest-from-the-match first: the
        // first tail-calls the second, which tail-calls the matched
        // copy loop. Both inherit the match, and the chain pays the
        // penalty once, not per hop, so both stand at one score — the
        // whole chain collapses into the same downstream decision.
        let mut program = program();
        program.listing.push(summary("FUN_180099999"));
        program.listing.push(summary("FUN_180098765"));
        program.bodies.insert(
            "FUN_180099999".into(),
            function(
                "FUN_180099999",
                "undefined8 * __fastcall FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  return FUN_180098765(param_1, param_2, param_3);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180098765".into(),
            function(
                "FUN_180098765",
                "undefined8 * __fastcall FUN_180098765(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  return FUN_18003ab00(param_1, param_2, param_3);\n",
            ),
        );
        let result = scan(program).await;

        for name in ["FUN_180099999", "FUN_180098765"] {
            let claims: Vec<&LibmatchFinding> = result.for_function(name).collect();
            assert_eq!(claims.len(), 1, "{name} inherits one claim");
            assert_eq!(claims[0].kind(), "tail_call_thunk");
            assert_eq!(claims[0].target(), "memcpy");
            assert_eq!(
                claims[0].confidence().value(),
                50,
                "the chain pays the penalty once, not per hop"
            );
        }
    }

    #[tokio::test]
    async fn propagation_leaves_unrelated_bodies_unclaimed() {
        // Three bodies the pass must leave silent: a one-line call to
        // an *unmatched* function, a body that calls a matched
        // function but has more to do than call, and a duplicate of an
        // unmatched body. The matched function keeps its own claim.
        let mut program = program();
        program.listing.push(summary("FUN_180099999"));
        program.listing.push(summary("FUN_180098765"));
        program.listing.push(summary("FUN_180097777"));
        program.bodies.insert(
            "FUN_180099999".into(),
            function(
                "FUN_180099999",
                "undefined8 * __fastcall FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  return FUN_1800412a0(param_1, param_2, param_3);\n",
            ),
        );
        program.bodies.insert(
            "FUN_180098765".into(),
            function(
                "FUN_180098765",
                "undefined8 * __fastcall FUN_180098765(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  lVar1 = FUN_18003ab00(param_1, param_2, param_3);\n  lVar1 = lVar1 + 1;\n  return lVar1;\n",
            ),
        );
        program.bodies.insert(
            "FUN_180097777".into(),
            function(
                "FUN_180097777",
                "undefined8 * __fastcall FUN_180097777(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                GUARDED_COPY_BODY,
            ),
        );
        let result = scan(program).await;

        for name in ["FUN_180099999", "FUN_180098765", "FUN_180097777"] {
            assert!(
                result.for_function(name).next().is_none(),
                "{name} carries no finding"
            );
        }
        assert_eq!(result.findings.len(), 1, "only the matched body is claimed");
        assert_eq!(result.findings[0].function(), "FUN_18003ab00");
    }

    #[tokio::test]
    async fn cross_function_findings_append_after_the_per_function_findings() {
        // The thunk stands first in the listing and the identical
        // duplicate last, but the per-function walk's claim still
        // lands first: cross-function findings append after every
        // per-function finding, each group in listing order.
        let matcher = folded_copy_matcher();
        let mut program = FakeProgram {
            listing: vec![
                summary("FUN_180099999"),
                summary("FUN_18003ab00"),
                summary("thunk_FUN_180098765"),
            ],
            ..FakeProgram::default()
        };
        program.bodies.insert(
            "FUN_180099999".into(),
            function(
                "FUN_180099999",
                "undefined8 * __fastcall FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                "  return FUN_18003ab00(param_1, param_2, param_3);\n",
            ),
        );
        program.bodies.insert(
            "FUN_18003ab00".into(),
            function(
                "FUN_18003ab00",
                "undefined8 * __fastcall FUN_18003ab00(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        program.bodies.insert(
            "thunk_FUN_180098765".into(),
            function(
                "thunk_FUN_180098765",
                "undefined8 * __fastcall thunk_FUN_180098765(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        let result = LibmatchEngine::with_source(program)
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let order: Vec<(&str, &str)> = result
            .findings
            .iter()
            .map(|finding| (finding.function(), finding.kind()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("FUN_18003ab00", "body_signature"),
                ("thunk_FUN_180098765", "identical_body"),
                ("FUN_180099999", "tail_call_thunk"),
            ]
        );
    }

    /// Parse a signature-file document, for the tests that configure a
    /// scan from a supplied database. The documents are spelled as file
    /// contents on purpose: these tests pin the file format at the
    /// scan seam.
    fn database_document(json: &str) -> SignatureDatabase {
        serde_json::from_str(json).expect("the database document parses")
    }

    #[tokio::test]
    async fn a_scan_configured_from_a_supplied_database_recognizes_a_shape_only_the_file_carries() {
        // A supplied database teaches the scan shapes no built-in set
        // claims on its own: the guarded copy reads as `memmove` at
        // the entry's stated confidence, and the plain copy loop is
        // claimed by the file's own entry — without a stated
        // confidence, at the standard body-evidence score. And the
        // swap is whole: the file replaces the built-in set, so the
        // built-in `memcpy` claim is gone — what stands on the copy
        // loop is the file's entry, not the built-in one.
        let database = database_document(
            r#"{
                "signatures": [
                    {
                        "symbol": "memmove",
                        "family": "crt",
                        "match_patterns": ["\\bif \\(", "VAR = VAR \\+ -1", "while \\(VAR != 0\\)"],
                        "min_lines": 6,
                        "confidence": 75,
                        "suggestion": "overlapping slice copy — `copy_within`"
                    },
                    {
                        "symbol": "copy_loop",
                        "family": "crt",
                        "match_patterns": ["\\*\\([^;]*\\) = \\*\\(", "VAR = VAR \\+ -1", "while \\(VAR != 0\\)"],
                        "min_lines": 6,
                        "suggestion": "slice copy — `copy_nonoverlapping`"
                    }
                ]
            }"#,
        );
        let result = LibmatchEngine::with_source(program())
            .with_signature_database(database)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let guarded: Vec<&LibmatchFinding> = result.for_function("FUN_1800412a0").collect();
        assert_eq!(guarded.len(), 1, "the guarded copy fits the memmove entry");
        assert_eq!(guarded[0].target(), "memmove");
        assert_eq!(
            guarded[0].confidence().value(),
            75,
            "the finding scores at the entry's stated confidence"
        );

        let copy: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(copy.len(), 1);
        assert_eq!(
            copy[0].target(),
            "copy_loop",
            "the built-in memcpy claim is gone — the file replaces the set whole"
        );
        assert_eq!(
            copy[0].confidence().value(),
            crate::confidence::BODY_MATCH_CONFIDENCE,
            "an entry without a stated confidence scores at the standard body-evidence score"
        );
    }

    #[tokio::test]
    async fn required_and_forbidden_callee_references_gate_matching() {
        // An entry can require a callee reference — "calls `malloc`" —
        // and forbid one. The allocating copy fits only the entry that
        // requires the call; the plain copy loop fits only the entry
        // that forbids it.
        let mut program = program();
        program.listing.push(summary("FUN_18005cd00"));
        program.bodies.insert(
            "FUN_18005cd00".into(),
            function(
                "FUN_18005cd00",
                "undefined8 * __fastcall FUN_18005cd00(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                ALLOCATING_COPY_BODY,
            ),
        );
        let copy_shapes = [
            r"\*\([^;]*\) = \*\(",
            r"VAR = VAR \+ -1",
            r"while \(VAR != 0\)",
        ];
        let database = SignatureDatabase {
            signatures: vec![
                LibmatchSignature::new(
                    "allocating_copy",
                    LibraryFamily::Crt,
                    copy_shapes
                        .into_iter()
                        .map(|shape| shape.to_string())
                        .chain([r"\bmalloc\b".to_string()]),
                    "allocate and fill — `Vec::with_capacity` plus a copy",
                ),
                LibmatchSignature::new(
                    "plain_copy",
                    LibraryFamily::Crt,
                    copy_shapes,
                    "slice copy — `copy_nonoverlapping`",
                )
                .with_exclusions([r"\bmalloc\b"]),
            ],
        };
        let result = LibmatchEngine::with_source(program)
            .with_signature_database(database)
            .scan("eqmain.dll")
            .await
            .expect("scan");

        let plain: Vec<&LibmatchFinding> = result.for_function("FUN_18003ab00").collect();
        assert_eq!(plain.len(), 1);
        assert_eq!(
            plain[0].target(),
            "plain_copy",
            "the copy without a malloc call fits the entry forbidding the reference"
        );

        let allocating: Vec<&LibmatchFinding> = result.for_function("FUN_18005cd00").collect();
        assert_eq!(allocating.len(), 1);
        assert_eq!(
            allocating[0].target(),
            "allocating_copy",
            "only the entry requiring the malloc call fits the allocating copy"
        );
    }

    #[tokio::test]
    async fn a_failing_listing_fails_the_whole_run() {
        // With the listing gone nothing was scanned, so the run aborts
        // rather than returning a result that looks empty by detection.
        let mut program = program();
        program.fail_listing = true;
        let result = LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        assert!(matches!(
            result,
            Err(crate::LibmatchError::Engine(EngineError::Reported { .. }))
        ));
    }

    #[tokio::test]
    async fn an_empty_program_yields_an_empty_result() {
        let result = scan(FakeProgram::default()).await;
        assert!(result.is_empty());
        assert_eq!(result.metadata.binary, "eqmain.dll");
    }

    #[tokio::test]
    async fn a_function_that_will_not_decompile_is_skipped() {
        // The thunk that will not decompile passes unrecorded; the
        // memcpy function beside it still lands its finding.
        let mut program = program();
        program.listing.insert(0, summary("thunk_180010000"));
        program.fail_decompiles.push("thunk_180010000".into());
        let result = scan(program).await;

        assert!(result.for_function("thunk_180010000").next().is_none());
        assert_eq!(result.for_function("FUN_18003ab00").count(), 1);
    }

    #[tokio::test]
    async fn a_scan_where_every_decompile_fails_aborts() {
        // The skip-rate breaker: most of the listing failing to
        // decompile is the engine answering from the wrong program, and
        // an empty result would persist as a phantom-clean record.
        let mut program = program();
        program.fail_decompiles = program
            .listing
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        let result = LibmatchEngine::with_source(program)
            .scan("eqmain.dll")
            .await;
        // The breaker trips as soon as most of the listing has failed —
        // two of three — not only after all of them.
        assert!(matches!(
            result,
            Err(crate::LibmatchError::DecompileBreaker {
                failed: 2,
                total: 3
            })
        ));
    }

    #[tokio::test]
    async fn the_scan_stamps_its_provenance() {
        let result = scan(program()).await;
        let engine = result
            .metadata
            .engine
            .expect("the fake source names its engine");
        assert_eq!(engine.name, "fake-engine");
        assert_eq!(engine.version.as_deref(), Some("9.9"));
        assert_eq!(engine.fingerprint.as_deref(), Some("0123456"));
    }

    // ============================================================
    // Admitted scan coverage (issue #347)
    // ============================================================

    /// The data-level verdict of the roster pin: empty means the record
    /// names every declared facet exactly once, and each fault spells one
    /// drift.
    fn roster_faults(coverage: &ScanCoverage) -> Vec<String> {
        coverage.roster_faults(DECLARED_FACETS)
    }

    #[tokio::test]
    async fn a_fresh_scan_stamps_complete_bodies_coverage_and_a_clean_roster() {
        // The stamp rides the engine's own scan, not the registry row
        // and not the CLI — the batch scan phase and the CLI's
        // force-rescan file the same admission through this one
        // definition. Every body was read here, so the record is
        // complete and says nothing needs admitting.
        let result = scan(program()).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a fresh libmatch scan states its coverage");
        assert_eq!(coverage.status, CoverageStatus::Complete);
        assert!(
            roster_faults(&coverage).is_empty(),
            "a fresh document must name every declared facet exactly once"
        );
        let bodies = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Complete);
        assert_eq!(
            bodies.limitation, None,
            "a scan that read every body admits nothing — and silence now \
             means examined-and-clean, not unchecked"
        );
    }

    #[tokio::test]
    async fn a_decompiled_failure_is_admitted_by_name_on_the_coverage_record() {
        // The whole point of the admission: a body the scan could not
        // read is named, so it is never mistaken for an examined-and-
        // clean function the findings simply left unmentioned.
        let mut program = program();
        program.fail_decompiles = vec!["FUN_18003e750".into()];
        let result = scan(program).await;
        let coverage = result
            .metadata
            .coverage
            .expect("a partial libmatch scan states its coverage too");
        assert_eq!(
            coverage.status,
            CoverageStatus::Partial,
            "the whole picture mirrors the one facet it examined"
        );
        assert!(
            roster_faults(&coverage).is_empty(),
            "a partial scan still names every declared facet exactly once"
        );
        let bodies = coverage
            .facets
            .iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Partial);
        assert_eq!(
            bodies.limitation.as_deref(),
            Some("1 function body unreached: FUN_18003e750"),
            "the unreached body is named, and only the unreached body"
        );
    }

    #[tokio::test]
    async fn the_coverage_line_is_capped_at_five_names_and_counts_the_nameless() {
        // Bounded prose beside the counts: six decompile failures name
        // five inline and fold the sixth into a count, and a nameless
        // listing entry counts toward the total without stealing a name
        // slot.
        let names: Vec<String> = (0..12).map(|i| format!("FUN_body_{i:04}")).collect();
        let mut program = tests::FakeProgram::default();
        for (index, name) in names.iter().enumerate() {
            program.listing.push(FunctionSummary {
                name: name.clone(),
                address: 0x1800_0000 + index as u64,
            });
            if index >= 6 {
                program.bodies.insert(
                    name.clone(),
                    function(name, "undefined FUN_body_x(void)", PLAIN_BODY),
                );
            }
        }
        program.fail_decompiles = names[..6].to_vec();
        program.listing.push(summary(""));
        let result = scan(program).await;
        let bodies = result
            .metadata
            .coverage
            .expect("a partial libmatch scan states its coverage")
            .facets
            .into_iter()
            .find(|facet| facet.id == "function-bodies")
            .expect("function-bodies is named");
        assert_eq!(bodies.status, CoverageStatus::Partial);
        assert_eq!(
            bodies.limitation.as_deref(),
            Some(
                "7 function bodies unreached: FUN_body_0000, FUN_body_0001, \
                 FUN_body_0002, FUN_body_0003, FUN_body_0004, +2 more"
            ),
            "six named failures plus one nameless entry: five names, the \
             rest counted, the count covering both"
        );
    }

    #[tokio::test]
    async fn every_finding_a_fresh_scan_makes_states_its_own_version_authority() {
        // The per-finding admission rides the record (P19-3): the body
        // signature proved a shape, never WHICH release carried it, and
        // every consumer reading the document — report, prompt, a
        // `--show` months later — sees the note beside the match.
        let result = scan(program()).await;
        assert!(
            !result.findings.is_empty(),
            "the fixture program lands at least one match"
        );
        for finding in &result.findings {
            assert_eq!(
                finding.admission(),
                crate::types::VERSION_UNKNOWN_ADMISSION,
                "match `{}` names a version the signature never established",
                finding.function()
            );
        }
    }

    #[tokio::test]
    async fn an_inherited_claim_carries_the_admission_it_inherited_from() {
        // A propagated match admits exactly what the match it was
        // inherited from admits — the linker-folded copy claims the same
        // symbol on the same (un)authority.
        let matcher = folded_copy_matcher();
        let mut program = program();
        program.listing.push(summary("thunk_FUN_180099999"));
        program.bodies.insert(
            "thunk_FUN_180099999".into(),
            function(
                "thunk_FUN_180099999",
                "undefined8 * __fastcall thunk_FUN_180099999(undefined8 *param_1,undefined8 *param_2,ulong param_3)",
                MEMCPY_BODY,
            ),
        );
        let result = LibmatchEngine::with_source(program)
            .with_matcher(matcher)
            .scan("eqmain.dll")
            .await
            .expect("scan");
        let claims: Vec<&LibmatchFinding> = result.for_function("thunk_FUN_180099999").collect();
        assert_eq!(claims.len(), 1, "the duplicate inherits one claim");
        assert_eq!(claims[0].kind(), "identical_body");
        assert_eq!(
            claims[0].admission(),
            crate::types::VERSION_UNKNOWN_ADMISSION
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_declared_facet_goes_missing() {
        let mut coverage = coverage_stamp(&[], 0);
        coverage
            .facets
            .retain(|facet| facet.id != "function-bodies");
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `function-bodies` is missing from the record"],
            "an engine quietly dropping its one facet fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_a_facet_is_doubled() {
        let mut coverage = coverage_stamp(&["FUN_18003e750".to_string()], 0);
        coverage.facets.push(coverage.facets[0].clone());
        assert_eq!(
            roster_faults(&coverage),
            ["declared facet `function-bodies` appears 2 times in the record"],
            "a facet crowded into two entries fails loudly"
        );
    }

    #[test]
    fn the_roster_pin_fails_when_coverage_names_an_orphan_facet() {
        let mut coverage = coverage_stamp(&[], 0);
        coverage.facets.push(FacetCoverage {
            id: "string-literals".to_string(),
            status: CoverageStatus::Unexamined,
            limitation: None,
        });
        assert_eq!(
            roster_faults(&coverage),
            ["record names `string-literals`, a facet the engine never declared"],
            "an id invented outside the declared roster fails loudly"
        );
    }
}
