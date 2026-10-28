//! Error-handling idiom evidence: the scan reads the try/catch frame,
//! the named handler registrations, and the failure codes out of kept
//! function bodies. The reading is decompile-level, persisted per
//! binary, and the same document holds the failure codes a body hands
//! back or guards against.
//!
//! This crate is the growing slice of P15 (the error-handling
//! recovery pass). It detects the error-handling shapes visible in
//! kept body text: an SEH `try`/`catch` frame the decompiler spelled
//! outright, a named personality-handler thunk registration where the
//! decompiler left the frame undrawn, an exception-API call, a direct
//! `RaiseException` call, and the goto-cleanup ladder of guarded
//! forward gotos converging on one releasing join block. It persists
//! the findings as an evidence document under
//! `re/analysis/errhandling/`. A failure code the function returns,
//! raises, or compares for gets one record of its own per distinct
//! code per function: it names the failure contract without reading
//! the body. Those records are keyed to the function and sit beside
//! the idiom findings.
//!
//! The second-hand records sit beside them too. The cross-function
//! pass copies a callee's recorded failure codes onto the callers that
//! guard on the callee's result or return it again. Only codes travel;
//! idioms never do. The copies score at a confidence penalty below
//! every band that saw the literal value first-hand (ADR-0047). The
//! whole-program pass and the prompt consumers are follow-up issues
//! against this same artifact, and nothing here feeds an annotation
//! prompt or a translation yet (ADR-0046).
//!
//! The SEH readings rank on ADR-0046's family ladder, and the scan
//! keeps one claim per function. The strongest SEH family that fires
//! wins. A `RaiseException` finding is kept beside it as a different
//! fact, and a goto-cleanup ladder beside both as a third fact. A GS
//! stack-canary check never reads as exception handling; it is
//! compiler noise, already stripped by the shipped decompiler-noise
//! filter.
//!
//! The reading is decompile-level only: one function's body text at a
//! time. No disassembly, no CFG, no call-fact reads, and nothing
//! written back to the program (ADR-0020). An earlier draft of the
//! pass was rejected for exactly those violations. The catalog's
//! whole-program frame rule (ADR-0023) stays a future reading; this
//! artifact prepares for it (ADR-0046). The cross-function pass is
//! the one reading that relates two bodies. It reads the call edges
//! out of the kept bodies themselves — the shared `call_sites` scan,
//! never a call-graph query — and stops after one hop. At one hop, the
//! callee's record and the call-site evidence already let a reader
//! chase the chain by hand (ADR-0047).
//!
//! Architecture:
//! - [`types`] — the finding records, the tagged finding union, and
//!   the metadata-stamped per-binary result.
//! - [`seh_frame`] — the spelled `try`/`catch` frame detector: pure
//!   text analysis of one kept body.
//! - [`named_handler`] — the named personality-handler thunk
//!   detector, the frame read through its registered handler.
//! - [`exception_api`] — the exception-API call detector, SEH
//!   participation read through the API alone.
//! - [`raise_exception`] — the direct `RaiseException` detector,
//!   naming the raised code when the argument is a literal.
//! - [`goto_cleanup`] — the goto-cleanup ladder detector: guarded
//!   forward gotos converging on one join block that releases or
//!   returns a constant.
//! - [`error_code`] — the failure-code detector: HRESULT- and
//!   NTSTATUS-shaped literals at return, raise, and guard sites,
//!   one record per distinct code per function at its strongest site.
//! - [`cross_function`] — the propagation pass: it copies recorded
//!   codes along the call map onto the guards and re-returns, one
//!   claim per code per function, at the inherited band.
//! - [`identifier`] — the shared whole-identifier boundary rule the
//!   name-based detectors read through.
//! - [`engine`] — [`ErrhandlingEngine`]: decompiles every function
//!   listing entry once, detects the idioms on each kept body, and
//!   assembles the metadata-stamped result.
//! - [`persist`] — [`ErrhandlingPersistor`]: strict JSON at
//!   `re/analysis/errhandling/<basename>.json` (ADR-0043).
//! - [`error`] — the crate's error type.

pub mod cross_function;
pub mod engine;
pub mod error;
pub mod error_code;
pub mod exception_api;
pub mod goto_cleanup;
pub mod identifier;
pub mod named_handler;
pub mod persist;
pub mod raise_exception;
pub mod seh_frame;
pub mod types;

pub use cross_function::{CrossFunctionAnalyzer, INHERITED_ERROR_CODE_CONFIDENCE};
pub use engine::ErrhandlingEngine;
pub use error::{ErrhandlingError, Result};
pub use error_code::{
    ERROR_CODE_GUARD_CONFIDENCE, ERROR_CODE_RAISE_CONFIDENCE, ERROR_CODE_RETURN_CONFIDENCE,
    ERROR_CODE_SUGGESTION, ErrorCodeDetector,
};
pub use exception_api::{EXCEPTION_API_NAMES, ExceptionApiDetector};
pub use goto_cleanup::{
    GOTO_CLEANUP_RELEASE_CONFIDENCE, GOTO_CLEANUP_RETURN_CONFIDENCE, GOTO_CLEANUP_SUGGESTION,
    GotoCleanupDetector, RELEASE_API_NAMES,
};
pub use named_handler::{NamedHandlerDetector, PERSONALITY_HANDLER_THUNKS};
pub use persist::ErrhandlingPersistor;
pub use raise_exception::{
    RAISE_EXCEPTION_API, RAISE_EXCEPTION_SUGGESTION, RaiseExceptionDetector,
};
pub use seh_frame::{SEH_FRAME_SUGGESTION, SPELLED_FRAME_CONFIDENCE, SehFrameDetector};
pub use types::{
    ErrhandlingFinding, ErrhandlingResult, ErrorCode, ErrorCodeSite, ExceptionApiCall, GotoCleanup,
    InheritedErrorCode, NamedHandler, RaiseException, SehFrame,
};
