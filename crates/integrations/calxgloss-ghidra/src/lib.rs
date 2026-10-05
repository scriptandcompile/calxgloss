//! Client for the GhidraMCP HTTP API.
//!
//! # The shape of the API
//!
//! GhidraMCP serves whichever program is current in the running Ghidra instance
//! over a flat set of endpoints. There are no sessions and no per-DLL routing:
//! a request names an address or a symbol, and the current program answers.
//! The 6.x bridge can hold several programs open at once and move which one is
//! current with `switch_program`; everything else still addresses the current
//! program only.
//!
//! Three consequences shape this client:
//!
//! * **Most responses are `text/plain`,** not JSON, so [`parse`] holds the
//!   record formats rather than serde. A handful of 6.x endpoints
//!   (`get_current_address`, `get_current_function`, `list_imports`,
//!   `list_open_programs`) answer JSON, and their parsers accept both shapes.
//! * **Failures arrive as `200 OK` with an explanation in the body** — a
//!   plain-text line or a `{"error": "..."}` object. Every response is passed
//!   through [`error::classify`] before its content is parsed; see that module
//!   for why this is not optional.
//! * **Endpoint names changed** between the old bridge and the 6.x one
//!   (`segments` → `list_segments`, `xrefs_to` → `get_xrefs_to`,
//!   `searchFunctions` → `search_functions`, …). The paths below follow the
//!   6.x bridge, which listens on port 8080 by default.

mod client;
mod error;
mod model;
pub mod parse;

pub use client::{GhidraClient, GhidraConfig, GhidraError, ProgramInfo, Result, rva_from_va};
pub use error::Classification;
pub use model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionBody,
    FunctionReport, FunctionSummary, OpenProgram, Segment, StringLiteral, StructFieldLayout,
    StructLayout, Symbol, Xref,
};
