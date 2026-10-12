//! Axum handler functions for the review dashboard API.
//!
//! Handlers are organized into feature-based submodules for readability.

mod analysis;
mod api;
mod batch;
mod classification;
mod diff;
mod gc;
mod ghidra;
mod llm_io;
mod overrides;
mod pipeline;
mod process;
mod queue;
mod scope;
mod r#static;
mod summary;

pub use self::api::*;
pub use self::batch::*;
pub use self::classification::*;
pub use self::diff::*;
pub use self::gc::*;
pub use self::ghidra::*;
pub use self::llm_io::*;
pub use self::overrides::*;
pub use self::pipeline::*;
pub use self::queue::*;
pub use self::scope::*;
pub use self::r#static::*;
pub use self::summary::*;
