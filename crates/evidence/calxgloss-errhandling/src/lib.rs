//! Error-handling idiom evidence: reading the try/catch frame, named
//! handlers and failure codes from kept function bodies as
//! decompile-level evidence, persisted per binary, alongside the
//! failure codes a body hands back or guards against.
//!
//! This crate is the growing slice of P15 (the error-handling
//! recovery pass): it detects the error-handling shapes kept body
//! text carries — an SEH `try`/`catch` frame the decompiler spelled
//! outright, a named personality-handler thunk registration where it
//! left the frame undrawn, an exception-API call, a direct
//! `RaiseException` call, and the goto-cleanup ladder of guarded
//! forward gotos converging on one releasing join block — and
//! persists the findings as an evidence document under
//! `re/analysis/errhandling/`. A failure code the function returns,
//! raises, or compares for is one record of its own per distinct code
//! per function — the failure contract named without reading the
//! body — keyed to the function beside the idiom findings. It
//! deliberately stops there: the cross-function propagation reading,
//! the whole-program pass and the prompt consumers are follow-up
//! issues against this same artifact, and nothing here feeds an
//! annotation prompt or a translation yet (ADR-0046).
//!
//! The SEH readings rank on ADR-0046's family ladder and the engine
//! keeps one claim per function: the strongest SEH family that fires
//! wins, a `RaiseException` finding rides beside it as a different
//! fact, a goto-cleanup ladder rides beside both as a third fact,
//! and a GS stack-canary check — compiler noise, already
//! stripped by the shipped decompiler-noise filter — never reads as
//! exception handling.
//!
//! The reading is decompile-level only — per-function body text. No
//! disassembly, no CFG, no call-fact reads, and nothing written back
//! to the program (ADR-0020); an earlier draft of the pass was
//! rejected for exactly those violations, and the catalog's
//! whole-program frame rule (ADR-0023) stays a future reading this
//! artifact prepares (ADR-0046).
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
//! - [`identifier`] — the shared whole-identifier boundary rule the
//!   name-based detectors read through.
//! - [`engine`] — [`ErrhandlingEngine`]: decompiles every function
//!   listing entry once, detects the idioms on each kept body, and
//!   assembles the metadata-stamped result.
//! - [`persist`] — [`ErrhandlingPersistor`]: strict JSON at
//!   `re/analysis/errhandling/<basename>.json` (ADR-0043).
//! - [`error`] — the crate's error type.

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
    NamedHandler, RaiseException, SehFrame,
};
