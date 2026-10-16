//! Checked-in test fixtures shared by the analysis engine test harnesses.
//!
//! The fixture target binary is a small x86-64 Windows PE DLL compiled from
//! `fixtures/fixture_target.c` by this crate's build script — built from
//! source as part of the test fixtures, with no manual steps and no
//! proprietary code. Its shape is the contract the Kuna engine tests (and
//! any future engine test) assert against: named exports, imports from two
//! DLLs, string literals, and a switch the compiler lowers to a jump table.
//!
//! # Architecture
//!
//! - `error.rs` — `TestFixturesError` and the crate-wide `Result` alias.
//! - root — the fixture shape constants and the fixture loader, landing in
//!   the feature commit on top of this scaffold.

pub mod error;

pub use error::{Result, TestFixturesError};
