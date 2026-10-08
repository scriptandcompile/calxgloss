//! Axum handler functions for the review dashboard API.
//!
//! Handlers are organized into feature-based submodules for readability.

mod api;
mod diff;
mod gc;
mod ghidra;
mod pipeline;
mod process;
mod queue;
mod r#static;
mod summary;

pub use self::api::*;
pub use self::diff::*;
pub use self::gc::*;
pub use self::ghidra::*;
pub use self::pipeline::*;
pub use self::queue::*;
pub use self::r#static::*;
pub use self::summary::*;
