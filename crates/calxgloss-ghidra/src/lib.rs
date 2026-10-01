//! Client for the GhidraMCP HTTP API.
//!
//! # The shape of the API
//!
//! GhidraMCP serves whichever program is open in the running Ghidra instance
//! over a flat set of endpoints. There are no sessions, no target executables in
//! the path, and no per-DLL routing: a request names an address or a symbol, and
//! the open program answers.
//!
//! Two consequences shape this client:
//!
//! * **Responses are `text/plain`,** not JSON, so [`parse`] holds the record
//!   formats rather than serde.
//! * **Failures arrive as `200 OK` with an explanation in the body.** Every
//!   response is passed through [`error::classify`] before its content is
//!   parsed; see that module for why this is not optional.

mod client;
mod error;
mod model;
pub mod parse;

pub use client::{GhidraClient, GhidraConfig, GhidraError, ProgramInfo, Result, rva_from_va};
pub use error::Classification;
pub use model::{
    DecompiledFunction, FunctionBody, FunctionReport, FunctionSummary, Segment, StringLiteral,
    Symbol, Xref,
};
