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
//!
//! On top of the raw client, [`ScanSource`] is the shared read-only seam the
//! evidence engines pull their program facts through; [`GhidraClient`]
//! implements it, and [`CachedGhidraSource`] implements it once more as the
//! two-tier read cache every engine will read through.
//!
//! The [`lifecycle`] module holds the read-only stack checks — Ghidra install
//! discovery, the per-version GhidraMCP extension pairing, and the server
//! identity probe — that `calxgloss doctor` reports and later preflights run,
//! plus the wrong-program guard that verifies the server is serving the scan
//! target before any scan runs (the 2026-10-08 incident fix).

mod cache;
mod client;
mod error;
pub mod lifecycle;
mod model;
pub mod parse;
mod scan_source;

pub use cache::CachedGhidraSource;
pub use client::{
    GhidraClient, GhidraConfig, GhidraError, MIN_PLUGIN_VERSION, ProgramInfo, Result,
    plugin_version_at_least, rva_from_va,
};
pub use error::Classification;
pub use model::{
    DataItem, DataTypeEntry, DecompiledFunction, EnumDefinition, EnumMember, FunctionBody,
    FunctionReport, FunctionSummary, OpenProgram, Segment, ServerInfo, ServerKind, StringLiteral,
    StructFieldLayout, StructLayout, Symbol, Xref,
};
pub use scan_source::{PipelineSource, ScanSource};
